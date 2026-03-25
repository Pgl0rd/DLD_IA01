from __future__ import annotations

import asyncio
import argparse
import logging
from typing import List, Sequence

from .config import AppConfig
from .correlator import UploadCorrelatorPublisher
from .context_provider import ContextProvider
from .sensors.browser_upload_sensor import BrowserUploadSensor
from .sensors.clipboard_sensor import ClipboardSensor
from .sensors.file_sensor import FileSensor
from .sensors.network_sensor import NetworkSensor
from .sensors.print_sensor import PrintSensor
from .sensors.process_sensor import ProcessSensor
from .sensors.usb_sensor import UsbSensor
from .transport import ReliableEventQueue, StdoutPublisher

logger = logging.getLogger(__name__)


class SensorRuntime:
    def __init__(self, config: AppConfig, selected_sensors: set[str] | None = None) -> None:
        self.config = config
        self.selected_sensors = selected_sensors
        self.context_provider = ContextProvider()
        publisher = UploadCorrelatorPublisher(StdoutPublisher())
        self.queue = ReliableEventQueue(config.queue, publisher)

    def _is_enabled(self, sensor_name: str) -> bool:
        enabled_in_config = self.config.sensors[sensor_name].enabled
        if not enabled_in_config:
            return False
        if not self.selected_sensors:
            return True
        return sensor_name in self.selected_sensors

    def _build_sensors(self) -> List:
        sensors = []
        if self._is_enabled("file_sensor"):
            sensors.append(
                FileSensor(
                    self.context_provider,
                    watch_paths=self.config.sensors["file_sensor"].watch_paths,
                )
            )
        if self._is_enabled("clipboard_sensor"):
            sensors.append(ClipboardSensor(self.context_provider))
        if self._is_enabled("process_sensor"):
            sensors.append(ProcessSensor(self.context_provider))
        if self._is_enabled("network_sensor"):
            sensors.append(
                NetworkSensor(self.context_provider, settings=self.config.network_sensor_config)
            )
        if self._is_enabled("usb_sensor"):
            sensors.append(UsbSensor(self.context_provider))
        if self._is_enabled("print_sensor"):
            sensors.append(PrintSensor(self.context_provider))
        if self._is_enabled("browser_upload_sensor"):
            sensor_cfg = self.config.browser_upload_sensor_config
            sensors.append(
                BrowserUploadSensor(
                    self.context_provider,
                    host=sensor_cfg.tcp_host,
                    port=sensor_cfg.tcp_port,
                )
            )
        return sensors

    async def run_forever(self) -> None:
        await self.queue.start()
        sensors = self._build_sensors()
        logger.info("Starting sensor runtime with %d sensors", len(sensors))
        tasks = [asyncio.create_task(sensor.run(self.queue.emit)) for sensor in sensors]
        try:
            await asyncio.gather(*tasks)
        except asyncio.CancelledError:
            logger.info("Sensor runtime cancelled")
            raise
        finally:
            logger.info("Stopping sensor runtime...")
            for task in tasks:
                task.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)
            await self.queue.stop()
            logger.info("Sensor runtime stopped")


def _parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run Layer 1 sensors.")
    parser.add_argument(
        "--sensor",
        action="append",
        dest="sensors",
        choices=[
            "file_sensor",
            "clipboard_sensor",
            "process_sensor",
            "network_sensor",
            "usb_sensor",
            "print_sensor",
            "browser_upload_sensor",
        ],
        help="Run only selected sensor(s). Can be repeated.",
    )
    parser.add_argument(
        "--watch-path",
        action="append",
        default=[],
        help="Watch path(s) for file_sensor. Can be repeated.",
    )
    return parser.parse_args(argv)


async def run(argv: Sequence[str] | None = None) -> None:
    args = _parse_args(argv)
    config = AppConfig()
    if args.watch_path:
        config.sensors["file_sensor"].watch_paths = args.watch_path
    selected = set(args.sensors) if args.sensors else None
    runtime = SensorRuntime(config, selected_sensors=selected)
    await runtime.run_forever()


if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s - %(message)s",
    )
    try:
        asyncio.run(run())
    except KeyboardInterrupt:
        logger.info("Interrupted by user, shutdown complete.")

