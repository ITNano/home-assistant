
import os
from os.path import dirname, basename, isfile, join
from threading import Lock

class PacketCapturer:
    """Reads network packet captures and provides a way to register
       callbacks to receive this data """

    from watchdog.events import FileSystemEventHandler

    def __init__(self, path):
        """Initializes and starts to monitor the given path """
        self.callbacks = []
        from watchdog.observers import Observer
        self.observer = Observer()
        self.observer.schedule(self.PacketCaptureHandler(self.on_event), path)
        self.observer.start()

    def on_event(self, packet_list):
        """Distributes new packets to registered callbacks """
        for callback in self.callbacks:
            callback(packet_list)

    def add_callback(self, callback):
        """Registers a callback for data """
        if callback is not None:
            self.callbacks.append(callback)

    def __del__(self):
        """Stop and remove path monitoring """
        if self.observer is not None:
            self.observer.stop()
            self.observer.join()
            self.observer = None

    class PacketCaptureHandler(FileSystemEventHandler):
        """Handler to handle pcap file read preprocessing """

        def __init__(self, callback):
            """Create a handler """
            super(PacketCapturer.PacketCaptureHandler, self).__init__()
            self.callback = callback
            self.lock = Lock()

        def on_created(self, event):
            """Reads, interprets and removes all pcap files in the monitored
               folder except for the newest one (due to tcpdump impl.) """
            # Avoid concurrent reads from same files
            if not self.lock.acquire(blocking=False):
                return

            from scapy.all import rdpcap, PacketList
            path = dirname(event.src_path)
            # Ignore directories and the most recent created file
            all_files = [f for f in os.listdir(path) if isfile(join(path, f))]
            files = list(filter(pcap_filter(event.src_path), all_files))
            # Parse data from pcap format
            _LOGGER.info("Reading network files")
            data = [safe_exc(rdpcap, [], join(path, file)) for file in files]
            _LOGGER.info("Done reading network files")
            # Remove read files so data are only read once
            for file in files:
                os.remove(join(path, file))
            # Allow new files to be read
            self.lock.release()
            # Notify the user of the found data
            self.callback(PacketList([pkt for pkts in data for pkt in pkts]))


def safe_exc(func, default, *args):
    """Excecutes a function and discards all exceptions it causes."""
    try:
        return func(*args)
    except Exception:
        _LOGGER.warning("Caught an exception for Threat Detection.")
        return default


def pcap_filter(ignore_file):
    """Create filter to use for PacketCaptureHandler """
    def filter_func(file):
        """Filter to select .pcap files and ignore the given file """
        return file.endswith('.pcap') and file != basename(ignore_file)
    return filter_func