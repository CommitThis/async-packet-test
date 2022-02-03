from concurrent.futures import wait

class NotNakedAssertable(Exception):
    def __init__(self):
        super().__init__('The result value is not a boolean so cannot be used in a naked assert.')
class SniffFuture:
    def __init__(self, predicate, future):
        self._future = future
        self._result = None
        self._predicate = predicate

    def result(self):
        exception = self._future.exception()
        if exception is not None:
            raise exception
        self._result = self._future.result()
        return self._result

    def cancel(self):
        return self._future.cancel()

    def assert_value(self, value):
        result_ = self.result()
        assert(result_ == value), f'{self._predicate._detail()}'

    def assert_true(self):
        self.assert_value(True)
    
    def assert_false(self):
        self.assert_value(False)

    def __bool__(self):
        if self._result == None:
            self.result()
        if not isinstance(self._result, bool):
            raise NotNakedAssertable()
        return self._result

    def __repr__(self):
        if self._future.done():
            return f'SniffFuture(done={self._future.done()}, result={self._result})'
