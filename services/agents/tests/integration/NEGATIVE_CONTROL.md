# Negative control — `/readyz` through a broker outage

The fix is one line of wiring, so the thing worth recording is that reverting
that one line puts the defect back and the suite notices.

## What was reverted

In `test_readyz_broker_live.py::_readyz`, the dependency probe was changed
back to the flag the service used to register:

```diff
-    register_dependency(app, "kafka", worker.broker_reachable)
+    register_dependency(app, "kafka", lambda: worker.attached)
```

## Observed

Against a real `confluentinc/cp-kafka:7.5.0` broker advertising the proxy's
port, with the proxy then stopped:

```
>  assert status == 503, f"/readyz stayed green through a broker outage: {body}"
E  AssertionError: /readyz stayed green through a broker outage:
E    {'status': 'ready', 'service': 'aisoc-agents', 'kafka': True,
E     'subscriptions': {'aisoc.readyz.probe.42657': {'attached': True}}}
E  assert 200 == 503

ERROR aiokafka:client.py:435 Unable connect to node with id 1: [Errno 61] Connect call failed ('127.0.0.1', 59193)
ERROR aiokafka:client.py:325 Unable to update metadata from [1]
ERROR aiokafka.consumer.fetcher:fetcher.py:749 Failed fetch messages from 1: NodeNotReadyError
```

That is the live pass's finding reproduced exactly: HTTP 200, `status: ready`,
the subscription flag still true, and the client logging that it cannot reach
the broker at the same instant. With `broker_reachable` registered the same
run answers 503 `degraded` with `kafka: false`.

## The premise the suite also checks

`assert worker.attached is True` after the outage is deliberate and is not
redundant. If aiokafka ever stops iterating on a dead broker, the flag would
be sufficient after all and this probe would be unnecessary work — so that
assertion carries a message telling the next reader to re-check the premise
rather than the fix.
