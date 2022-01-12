---
title: Docs
layout: home
---

{:logostyle: style="margin: 0px auto; width: 50%"}
![Logo](logo.png)
{: logostyle}

{:center: style="text-align: center"}
# Asynchronous Packet Testing
{: center}

Python library for writing simple and human readable tests for future expected
packets.
{: .fs-6 .fw-300 center}

---

## Overview

Async Packet Test is a Python library based on `scapy` that can test the
contents of yet to be received packets, as well as providing `pytest` 
integration for doing so.

The concept came from writing packet processing pipelines in the
[P4 programming language](), where I wanted to write tests for end to end 
changes to and the receipt of packets, treating the pipeline itself as a closed
and mysterious box. That and the [Packet Test Framework]() I found to be highly
coupled and far too detailed/verbose for writing simple tests.

The concept is that, we have an expectation that at some point in the future, we
may expect to receive (or explicitly not receive!) a packet on some network
interface that matches some condition or property. 


```python
from async_packet_test.context import make_pytest_context
from async_packet_test.predicates import saw_dst_mac

context = make_pytest_context()

def test_saw_mac_broadcast(context):
    result = context.expect("eth0", saw_dst_mac("ff:ff:ff:ff:ff:ff"))
    result.assert_true()
```

<!-- That is to say, at some point in the future we expect that the `eth0` network
interface should see [MAC]() broadcast packet.


```python
from async_packet_test.context import TestContext
from scapy.all import Ether, ICMP, IP, sendp

context = TestContext()

pkt = Ether()/IP(src='10.0.0.1', dst='10.0.0.2')/ICMP()

test = context.expect('eth0', saw_packet_equals_sent(pkt))

# Send packet
sendp(pkt, iface='eth0')

assert(test.result() == True)
``` -->




## Installation

This is not currently on [PyPI](https://pypi.org/), and has to be installed
directly from the repository. 

```bash
git clone https://github.com/CommitThis/async-packet-test
cd async-packet-test && pip install .
```

### Permissions

If you wish to run the tests without using sudo (and the inevitable environment
preservation things you might have to do), you can do so, but you should
consider the security implications beforehand.

In order to open network sockets, a non-admin user can only do so if the
executable that does so has the appropriate permissions (called
[capabilities](https://man7.org/linux/man-pages/man7/capabilities.7.html)).

In this case the capability is `CAP_NET_RAW`

It would likely be considered unwise to apply such capabilities directly to the
system installed Python or [pytest](https://docs.pytest.org/en/6.2.x/). An
alternative approach would be to install it into a virtual Python environment,
which has taken copies of the Python executables:


```bash
python -m venv --copies .venv 
sudo setcap CAP_NET_RAW+eip .venv/bin/python
sudo setcap CAP_NET_RAW+eip .venv/bin/python3
sudo setcap CAP_NET_RAW+eip .venv/bin/pytest
```

> `setcap`... sets capabilities. `+eip` defines the "capability sets"; 
> `CAP_NET_RAW` is added to the executables effective (`e`) and permitted sets
> (`p`), and that any further process forks and threads will inherit (`i`) the
> capability set of the original executable. That's my understanding of it
> anyway.



## Usage

There are three main components of the library you will work with:

1. The `TestContext`. This is an object that is responsible for starting
   "expectations" on a specific network interface through the `expect`
   method, as well as manage their lifetime;
2. Test predicates, which are passed to an `expect` call and are the things
   that perform the tests on packets.
3. Finally, the test result.


### Test Context

The `TestContext` is used to start and manage running tests/expectations. It
takes no constructor arguments, and it's interface is simple:

```python
class TestContext:
    def expect(self
            iface: str,           # Network interface to bind to
            predicate: Predicate, # ... uh.. the test predicate
            timeout: float,       # Number of seconds before test is cancelled
            count: int):          # Number of packets before test is cancelled
        pass
    def stop(self):
        pass
```

That's all there is to it.

> There is a `monitor` method, but it is not well tested, it is functionality
> that can be achieved using an ordinary `scapy.AsyncSniffer` and may be removed
> in the future. It is therefore not recommended to be used.

### Test Predicates

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

```python
def test_saw_mac_address(context):
    dst_mac = 'ab:ab:ab:ab:ab:ab'
    iface = 'veth0'
    future = context.expect(iface, saw_dst_mac(dst_mac))
    assert(future.result() == True)
```

It may be obvious, but what this is saying that we want to test that at some
point in the future that `veth0` will see the supplied MAC adress. The `future`
from the `expect` call represents the outcome of the test. Consequently, when
retrieving the result, this call will block until the test completes.



### Writing Tests

```python
from async_packet_test.context import TestContext
from scapy.all import Ether, ICMP, IP, sendp

context = TestContext()
pkt = Ether()/IP(src='10.0.0.1', dst='10.0.0.2')/ICMP()
test = context.expect('eth0', saw_packet_equals_sent(pkt))

# Send packet
sendp(pkt, iface='eth0')

assert(test.result())
```

Predicates can be passed to an expect call as either a class or constructed
object. This is mainly for terseness; if a predicate doesn't accept any
constructor arguments, you can pass it's class and an object of that type will
be constructed for you:

```python
context.expect('eth0', received_packet)
```

There are a couple of different ways assertions can be defined:

```python
assert(test.result() == True)
assert(test.result() == 42)
test.assert_true()
test.assert_false()
test.assert_value(42)
```

For further examples, look at the [unit tests](https://github.com/CommitThis/async-packet-test/blob/main/test/test_predicates.py).


### Pytest Integration

Pytest integration is achieved by returning a test fixture that wraps a test
context.

```python
from async_packet_test.context import make_pytest_context
from async_packet_test.predicates import saw_dst_mac

context = make_pytest_context()

def test_saw_mac_broadcast(context):
    result = context.expect("eth0", saw_dst_mac("ff:ff:ff:ff:ff:ff"))
    result.assert_true()
```

Assuming that [permissions](#permissions) have been setup correctly, and the
library has been installed you should then be able to run

```bash
pytest
```

In you project.


### Built-in Predicates

* `received_packet`
* `timed_out`
* `saw_src_mac`
* `did_not_see_src_mac`
* `saw_dst_mac`
* `did_not_see_dst_mac`
* `saw_vlan_tag`
* `did_not_see_vlan_tag`
* `did_not_see_vlan`
* `saw_packet_equaling`
* `did_not_see_packet_equaling`
* `packet_count_was`
* `packet_count_was_less_than`
* `packet_count`
* `received_count_of`


### Writing Custom Predicates

This is relatively easy. The predicates are objects that test incoming packets,
and are able to carry state from one evaluation from the next. The base test is
as follows:

```python
class async_packet_test:
    def on_packet(self, pkt):
        pass

    def stop_condition(self, pkt) -> bool:
        pass

    def on_finish(self, timed_out) -> bool:
        pass
```

- `on_packet` receives avery packet. It is there for updating state.
- `stop_condition` is the to notify the test manager that the test has
  completed

- `on_finish` reports the result back to the manager, and ultimately the
  future given back to the user.

Carrying on with our previous example `saw_dst_mac` , the predicate is
constructed as follows:

```python
class saw_src_mac(async_packet_test):
    def __init__(self, mac):
        self._mac = mac

    def stop_condition(self, pkt):
        return pkt.haslayer(Ether) and pkt[Ether].src == self._mac

    def on_finish(self, timed_out):
        return not timed_out
```

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

```python
class packet_count_was(async_packet_test):
    def __init__(self, count):
        self._expected_count = count
        self._received_count = 0

    def on_packet(self, pkt):
        self._received_count += 1

    def on_finish(self, timed_out):
        return self._received_count == self._expected_count
```

As each packet is received, a counter will be incremented. At the end of the
time out period, the count will be compared with the expected result.

> The stop condition cannot be used for this purpose as it is called before the
> more general `on_packet` function.

It is important to note differences in between behaviour. This test expects a
specific number of packets, if the total count is off, it will return False.
However, it could equally be written so that it terminates as soon as the number
of packets are counted, that is to say, we care about the minimum number of
packets received, and not the total. This could be written as follows:

```python
class min_packet_count_was(async_packet_test):
    def __init__(self, count):
        self._expected_count = count
        self._received_count = 0

    def stop_condition(self, pkt):
        self._received_count += 1
        if self._received_count == self._expected_count:
            return True
        return False
```
