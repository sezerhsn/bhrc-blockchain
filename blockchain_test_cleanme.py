
bhrc_blockchain/tests/api/admin_routes_test.py ......................... [  3%]
.......................                                                  [  7%]
bhrc_blockchain/tests/api/auth_routes_test.py ......                     [  7%]
bhrc_blockchain/tests/api/auth_test.py ................................  [ 12%]
bhrc_blockchain/tests/api/chain_routes_test.py .............             [ 14%]
bhrc_blockchain/tests/api/contract_routes_test.py ...................... [ 17%]
....                                                                     [ 18%]
bhrc_blockchain/tests/api/dao_routes_test.py ........................... [ 22%]
.................                                                        [ 24%]
bhrc_blockchain/tests/api/export_routes_test.py ...............          [ 27%]
bhrc_blockchain/tests/api/multisig_routes_test.py ............           [ 28%]
bhrc_blockchain/tests/api/nft_routes_test.py ....                        [ 29%]
bhrc_blockchain/tests/api/panel_routes_test.py .............             [ 31%]
bhrc_blockchain/tests/api/token_routes_test.py 

=============================== warnings summary ===============================
bhrc_blockchain/database/models.py:7
bhrc_blockchain/database/models.py:7
  /root/bhrc_blockchain/bhrc_blockchain/database/models.py:7: MovedIn20Warning: The ``declarative_base()`` function is now available as sqlalchemy.orm.declarative_base(). (deprecated since: 2.0) (Background on SQLAlchemy 2.0 at: https://sqlalche.me/e/b8d9)
    Base = declarative_base()

../../usr/local/lib/python3.10/dist-packages/pydantic/_internal/_config.py:323
../../usr/local/lib/python3.10/dist-packages/pydantic/_internal/_config.py:323
  /usr/local/lib/python3.10/dist-packages/pydantic/_internal/_config.py:323: PydanticDeprecatedSince20: Support for class-based `config` is deprecated, use ConfigDict instead. Deprecated in Pydantic V2.0 to be removed in V3.0. See Pydantic V2 Migration Guide at https://errors.pydantic.dev/2.11/migration/
    warnings.warn(DEPRECATION_MESSAGE, DeprecationWarning)

bhrc_blockchain/network/notifications.py:7
bhrc_blockchain/network/notifications.py:7
  /root/bhrc_blockchain/bhrc_blockchain/network/notifications.py:7: DeprecationWarning: websockets.server.WebSocketServerProtocol is deprecated
    from websockets.server import WebSocketServerProtocol, serve

../../usr/local/lib/python3.10/dist-packages/websockets/legacy/__init__.py:6
../../usr/local/lib/python3.10/dist-packages/websockets/legacy/__init__.py:6
  /usr/local/lib/python3.10/dist-packages/websockets/legacy/__init__.py:6: DeprecationWarning: websockets.legacy is deprecated; see https://websockets.readthedocs.io/en/stable/howto/upgrade.html for upgrade instructions
    warnings.warn(  # deprecated in 14.0 - 2024-11-09

bhrc_blockchain/network/notifications.py:7
bhrc_blockchain/network/notifications.py:7
  /root/bhrc_blockchain/bhrc_blockchain/network/notifications.py:7: DeprecationWarning: websockets.server.serve is deprecated
    from websockets.server import WebSocketServerProtocol, serve

bhrc_blockchain/network/p2p.py:5
  /root/bhrc_blockchain/bhrc_blockchain/network/p2p.py:5: DeprecationWarning: websockets.server.WebSocketServerProtocol is deprecated
    from websockets.server import WebSocketServerProtocol, serve

bhrc_blockchain/network/p2p.py:5
  /root/bhrc_blockchain/bhrc_blockchain/network/p2p.py:5: DeprecationWarning: websockets.server.serve is deprecated
    from websockets.server import WebSocketServerProtocol, serve

bhrc_blockchain/network/p2p.py:6
  /root/bhrc_blockchain/bhrc_blockchain/network/p2p.py:6: DeprecationWarning: websockets.client.connect is deprecated
    from websockets.client import connect

bhrc_blockchain/tests/mempool_test.py:82
  /root/bhrc_blockchain/bhrc_blockchain/tests/mempool_test.py:82: PytestUnknownMarkWarning: Unknown pytest.mark.no_patch - is this a typo?  You can register custom marks to avoid this warning - for details, see https://docs.pytest.org/en/stable/how-to/mark.html
    @pytest.mark.no_patch

bhrc_blockchain/tests/mempool_test.py:96
  /root/bhrc_blockchain/bhrc_blockchain/tests/mempool_test.py:96: PytestUnknownMarkWarning: Unknown pytest.mark.no_patch - is this a typo?  You can register custom marks to avoid this warning - for details, see https://docs.pytest.org/en/stable/how-to/mark.html
    @pytest.mark.no_patch

bhrc_blockchain/tests/api/admin_routes_test.py::test_snapshot_rollback
bhrc_blockchain/tests/api/admin_routes_test.py::test_snapshot_rollback_success
  /root/bhrc_blockchain/bhrc_blockchain/core/snapshot/snapshot_manager.py:14: RuntimeWarning: coroutine 'emit_admin_alert' was never awaited
    emit_admin_alert("snapshot_created", {
  Enable tracemalloc to get traceback where the object was allocated.
  See https://docs.pytest.org/en/stable/how-to/capture-warnings.html#resource-warnings for more info.

bhrc_blockchain/tests/api/admin_routes_test.py::test_update_user_role
bhrc_blockchain/tests/api/admin_routes_test.py::test_update_user_role_user_not_found
bhrc_blockchain/tests/api/admin_routes_test.py::test_update_user_role_twice
bhrc_blockchain/tests/api/admin_routes_test.py::test_update_user_role_twice
bhrc_blockchain/tests/api/admin_routes_test.py::test_update_user_role_same_role
bhrc_blockchain/tests/api/admin_routes_test.py::test_update_role_user_not_found
bhrc_blockchain/tests/api/admin_routes_test.py::test_update_user_role_multiple_transitions
bhrc_blockchain/tests/api/admin_routes_test.py::test_update_user_role_multiple_transitions
bhrc_blockchain/tests/api/admin_routes_test.py::test_update_role_user_does_not_exist
  /usr/local/lib/python3.10/dist-packages/httpx/_models.py:408: DeprecationWarning: Use 'content=<...>' to upload raw bytes/text content.
    headers, stream = encode_request(

bhrc_blockchain/tests/api/chain_routes_test.py: 5 warnings
bhrc_blockchain/tests/api/panel_routes_test.py: 11 warnings
  /usr/local/lib/python3.10/dist-packages/starlette/templating.py:161: DeprecationWarning: The `name` is not the first parameter anymore. The first parameter should be the `Request` instance.
  Replace `TemplateResponse(name, {"request": request})` by `TemplateResponse(request, name)`.
    warnings.warn(

bhrc_blockchain/tests/api/multisig_routes_test.py::test_create_multisig
  /usr/local/lib/python3.10/dist-packages/_pytest/python.py:163: PytestReturnNotNoneWarning: Expected None, but bhrc_blockchain/tests/api/multisig_routes_test.py::test_create_multisig returned '46ac8b02-0fd3-47b4-bcf3-91d9488037c9', which will be an error in a future version of pytest.  Did you mean to use `assert` instead of `return`?
    warnings.warn(

-- Docs: https://docs.pytest.org/en/stable/how-to/capture-warnings.html
================================ tests coverage ================================

Name                                            Stmts   Miss  Cover
-------------------------------------------------------------------
bhrc_blockchain/core/blockchain/blockchain.py     194     87    55%
-------------------------------------------------------------------
TOTAL                                             194     87    55%
!!!!!!!!!!!!!!!!!!!!!!!!!!!!!! KeyboardInterrupt !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
/usr/lib/python3.10/threading.py:320: KeyboardInterrupt
(to show a full traceback on KeyboardInterrupt use --full-trace)
