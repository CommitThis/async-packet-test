from async_packet_test.sniff_future import SniffFuture
from async_packet_test.predicates import Predicate

from concurrent.futures import ThreadPoolExecutor
from threading import Lock, Event, Thread

from scapy.all import AsyncSniffer

import pytest


class TestContext:
    """Asynchronous Packet Test Context

    Context for matching packets against predicates.

    """

    __test__ = False # So pytest doesn't collect this class as a test

    DEFAULT_TIMEOUT = 5

    def __init__(self):
        self._executor = ThreadPoolExecutor(max_workers=4)
        self._monitors = []
        self._monitor_lock = Lock()

    def monitor(self, 
            iface: str,
            prn: callable=lambda p: print(p.summary()), # Function to apply against matching packet
            count: int=0, # 
            session=None, 
            filter: str=None,
            timeout=0,
            lfilter: callable=None):
        """Generic packet monitor.
        
        Listens on an interface with filter and applies a function to 
        each packet.

        Args:
            iface (str): Network interface to monitor
            prn (callable): Function to apply against matching packet
            count (int): Number of packets to capture. 0 is infinity
                (default is 0).
            session: A flow decoder, see scapy documentation
            filter (str): BPF filter (default is None)
            lfilter: Function to apply against packet to determine a
                match. (default is None)
    
        Raises:
            Exception: Raises when sniffer doesn't start
        """
        ready_event = Event()


        def notify_started():
            ''' Callback used by sniffer to event when it's actually started '''
            nonlocal ready_event
            ready_event.set()

        sniffer = AsyncSniffer(iface=iface, 
            session=session,
            count=count,
            prn=prn,
            monitor=True,
            filter=filter,
            lfilter=lfilter,
            timeout=timeout,
            started_callback=notify_started)

        sniffer.start()


        def join():
            ''' Start task to join sniffer, this will return as soon as the
            sniffer has finished, or until it's timeout has been reached.
            returns result which will be available through the future
            returned by the thread executor. '''
            nonlocal sniffer
            sniffer.join()


        ''' Wait until sniffer has actually started '''
        if not ready_event.wait(timeout=5):
            raise Exception('Sniffer did not start!')

        with self._monitor_lock:
            self._monitors.append(sniffer)

        return self._executor.submit(join)


    def stop(self):
        with self._monitor_lock:
            for monitor in self._monitors:
                if monitor.running:
                    monitor.stop()
            for monitor in self._monitors:
                monitor.join()

    
    def expect(self, 
            iface: str,
            predicate: Predicate,
            timeout: float=DEFAULT_TIMEOUT,
            count: int=0):
        '''Sniff for packets based on match predicate

        Launch a sniffer that looks for packets that match the supplied
        predicate. The idea is that you can use the function to "expect"
        some future result, and assert against it's result. As an example,
        you could write a predicate that looks for a source mac address:

            class saw_src_mac(Predicate):
                def __init__(self, mac):
                    self._mac = mac

                def stop_condition(self, pkt):
                    return pkt.haslayer(Ether) and pkt[Ether].src == self._mac

                def on_finish(self, timed_out):
                    return not timed_out

        Is used like the following:

            test = context.expect('eth0', saw_src_mac('ab:ab:ab:ab:ab:ab'))
            assert(test.result() == True)

        If the underlying sniffer sees a packet that matches, then the
        future's result will return True.

        Calling `result()` on the future will block until the condition is
        met, or the timeout is reached.

        Args:
            iface (str): Network interface to monitor
            predicate (Predicate): Function to apply against matching
                packet
            timeout (float): Period of time to monitor for packets.
            count (int): Number of packets to capture. 0 is infinity
                (default is 0).
        Raises:
            Exception: Raises when sniffer doesn't start
        Returns:
            SniffFuture: An object representing the monitor's future result
        '''

        # result = default_result
        ready_event = Event()
        timed_out = True
        error = None


        ''' For convenience, If predicate is class name because it takes no
            arguments, instantiate it. '''
        if isinstance(predicate, type):
            predicate = predicate()


        def stop_condition(pkt):
            ''' Wrapper for stop condition.
            
            This is wrapped so that if the the condition indicates
            that the sniffer should stop, the `timed_out` flag is unset;
            by default, it is `True`.
            '''
            # nonlocal result, expect, timed_out
            nonlocal predicate, timed_out, error
            try:
                should_stop: bool = predicate.stop_condition(pkt) 
                if should_stop == True:
                    timed_out = False
            except Exception as e:
                error = e
                sniffer.stop(join=False)

            return should_stop


        def on_packet(pkt):
            ''' Wrap `on_packet` function to capture any exceptions raised by
                the function and henceforth stop the sniffer.
                Referencing a nonlocal in a function defined before said
                nonlocal has been created makes me nervous... '''
            nonlocal predicate, error, sniffer
            try:
                predicate.on_packet(pkt)
            except Exception as e:
                error = e
                ''' Joining here raises an exception, probably because it is
                    an attempt to join within the thread to be joined. It seems
                    to work well enough without doing so'''
                sniffer.stop(join=False)


        def notify_started():
            ''' Callback used by sniffer to event when it's actually started '''
            nonlocal ready_event
            ready_event.set()


        sniffer = AsyncSniffer(iface=iface, 
            count=count,
            stop_filter=stop_condition,
            timeout=timeout,
            store=False,
            prn=on_packet,
            started_callback=notify_started)


        ''' Need the sniffer to start immediately '''
        sniffer.start()

        ''' Wait until sniffer has actually started '''
        if not ready_event.wait(timeout=5):
            raise Exception(f'Sniffer did not start on interface {iface}!')


        def join():
            ''' Start task to join sniffer, this will return as soon as the
            sniffer has finished, or until it's timeout has been reached.
            returns result which will be available through the future
            returned by the thread executor. '''
            nonlocal sniffer, timed_out, predicate, error

            sniffer.join()
            if error != None:
                raise error
            result = predicate.on_finish(timed_out)
            return result


        with self._monitor_lock:
            self._monitors.append(sniffer)

        return SniffFuture(predicate, self._executor.submit(join))



def make_pytest_context():
    @pytest.fixture(scope='module')
    def context_fixture():
        yield TestContext()
    return context_fixture