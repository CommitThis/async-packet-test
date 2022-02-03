# Asynchronous Packet Testing

This library aims to allow the creation of simple assertions and tests to be
run against packets that _may_ be received _in the future_. It's original
intent was to provide a black box testing framework for the P4.org Behavioural
Model, with no dependencies on any special P4 libraries, but I think it has some
utility outside of this context.

## Running

Because scapy is _usually_ required to be run as root (or at least with network
capture capabilities) the tests must also be run as root.

### Example Script

If installing into a virtual environment, running the example would involve:

    python3 -m venv .venv
    source .venv/bin/activate
    pip install .
    sudo .venv/bin/python ./example.py

> A safer alternative may be to create the virtual environment with
> copies of the python binaries from the host (rather than symlinks, as is the
> default behaviour), and then setting capabilities on them using `setcap`.


### Unit Tests

The unit tests require the use of a `dummy` interface. To that end, a script
has been fashioned which, using `poetry`:

* Installs and sources the virtual environment;
* Installs the packet test library;
* Using `sudo`, inserts the `dummy` kernel module and creates an interface;
* Using `sudo`, and preserving the poetry environment, runs the tests;
* Using `sudo`, removes the `dummy` interface and exits.


## A Simple Example

The following example creates a test for observing a single packet on the `lo`
(loopback) interface. 

```python
import pytest

from scapy.all import Ether, Dot1Q, TCP, IP, sendp

from async_packet_test.context import make_pytest_context
from async_packet_test.predicates import saw_vlan_tag

iface = 'lo'
context = make_pytest_context()
test_packet = Ether() / Dot1Q(vlan=102) / IP() / TCP()

def test_saw_vlan_102(context):
    result = context.expect(iface, saw_vlan_tag(102))
    sendp(test_packet, iface=iface)
    assert result

# You could use the `did_not_see_vlan_tag` predicate, however, this demonstrates
# a negated assertion. It also demonstrates the usage of a timeout. Otherwise
# the test would be sat waiting for a packet it will never see (until the
# default timeout is reached)
def test_did_not_see_vlan_103(context):
    result = context.expect(iface, saw_vlan_tag(103), timeout=0.5)
    sendp(test_packet, iface=iface)
    assert not result
```

## `pytest`

The test context file includes a `pytest` fixture, yielding a `TestContext`.
Therefore, the test context and predicates can be used to write unit tests.

The unit tests in `test/test_async_packet_test.py` should be fairly easy to grok.


## Test Predicates

The core purpose of this repository is testing switch functionality, which
involve the use of predicates which are applied against future packets,
I suppose asynchronously.

Predicates have been named to read naturally in English (even if it isn't my
strong suit) and read well in the context of the test. Even though they are
technically classes, in spite of `PEP` , they are written in the underscore
style. This is because they are used in a context where they could be perceived
as functions, and that lower case anything is easier to read and above all, in
my opinion (outside testing an outcome), unit tests should be comprehensible.
[[ citation needed ]]

Because they are testing something that _may_ happen in the future, they cannot
be evaluated immediately, and therefore their use may not be as obvious as other
testing frameworks.

As an example, we might want to test if a specific port saw a packet with a
particular MAC address.

    def test_saw_mac_address(context):
        dst_mac = 'ab:ab:ab:ab:ab:ab'
        iface = 'veth0'
        future = context.expect(iface, saw_dst_mac(dst_mac))
        assert(future.result() == True)

It may be obvious, but what this is saying that we want to test that at some
point in the future that `veth0` will see the supplied MAC adress. The `future`
from the `expect` call represents the outcome of the test. Consequently, when
retrieving the result, this call will block until the test completes.


### Writing Predicates

This is relatively easy. The predicates are objects that test incoming packets,
and are able to carry state from one evaluation from the next. The base test is
as follows:

    class async_packet_test:
        def on_packet(self, pkt):
            pass

        def stop_condition(self, pkt) -> bool:
            pass

        def on_finish(self, timed_out) -> bool:
            pass

- `on_packet` receives avery packet. It is there for updating state.
- `stop_condition` is the to notify the test manager that the test has
  completed

- `on_finish` reports the result back to the manager, and ultimately the
  future given back to the user.

Carrying on with our previous example `saw_dst_mac` , the predicate is
constructed as follows:

    class saw_src_mac(async_packet_test):
        def __init__(self, mac):
            self._mac = mac

        def stop_condition(self, pkt):
            return pkt.haslayer(Ether) and pkt[Ether].src == self._mac

        def on_finish(self, timed_out):
            return not timed_out

This is straightforward as no state is needed between packets; we only need to
test each individual packet for the supplied MAC address. As soon as that MAC is
seen, the test will terminate and `on_finish` will be called. Ultimately, the
only thing that needs to be returned is whether the test timed out, if it didn't
time out, the stop condition will never have returned `True` .

> `on_finish` could have been written by default to test whether or not it timed
> out however I wasn't sure whether that was reasonable behaviour or not.

Another simple example is testing the count of packets received.

> This may be difficult to guarantee as ports may receive packets for things
> like SSDP, multicast DNS, or any number of packets that may be sent to a port
> by the OS as a part of it's normal operation

    class packet_count_was(async_packet_test):
        def __init__(self, count):
            self._expected_count = count
            self._received_count = 0

        def on_packet(self, pkt):
            self._received_count += 1

        def on_finish(self, timed_out):
            return self._received_count == self._expected_count

As each packet is received, a counter will be incremented. At the end of the
time out period, the count will be compared with the expected result.

> The stop condition cannot be used for this purpose as it is called before the
> more general `on_packet` function.

It is important to note differences in between behaviour. This test expects a
specific number of packets, if the total count is off, it will return False.
However, it could equally be written so that it terminates as soon as the number
of packets are counted, that is to say, we care about the minimum number of
packets received, and not the total. This could be written as follows:

    class min_packet_count_was(async_packet_test):
        def __init__(self, count):
            self._expected_count = count
            self._received_count = 0

        def stop_condition(self, pkt):
            self._received_count += 1
            if self._received_count == self._expected_count:
                return True
            return False

