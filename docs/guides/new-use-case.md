# New use case

A use case is the only way into a context and runs inside one Unit of Work:
its database changes commit together or not at all. Layers and imports:
[arch §2](../architecture.md#2-layers-and-bounded-contexts),
[§14](../architecture.md#14-import-rules).

```python
@dataclass(frozen=True)
class DisableUser:
    user_id: UUID

class DisableUserHandler:
    def __init__(self, uow: UnitOfWork, clock: Clock) -> None:
        self._uow, self._clock = uow, clock

    async def __call__(self, cmd: DisableUser, actor: Principal) -> None:
        async with self._uow as uow:
            user = await uow.users.get(cmd.user_id)  # raises NotFound
            user.disable(at=self._clock.now())
            uow.devices.remove_all(user.id)
            uow.tasks.add(DisableIdentity(user.id))
            uow.audit.record(actor, "user.disable", target=user.id)
            await uow.commit()
```

- Command and use case in `application/`; leaving without `commit()` rolls back.
- No provider or email call inside: add a `tasks` row for the worker to
  retry ([arch §9](../architecture.md#9-administration)).
- Audit entries and notices go in the same Unit of Work.
- Raise domain errors ([arch §10](../architecture.md#10-error-model)).
- The route declares the scopes and gate of its
  [catalogue row](../spec/auth.md#9-clients-scopes-and-route-gates).
- Test on a fake Unit of Work: success commits; a failure after the first
  write commits nothing.
