"""Suite-wide guards.

run_benchmark.main() and phase2_setup.main() install the launcher's container
hygiene (sandbox/session.install_launcher_cleanup): a real `docker ps`, a
`docker rm -f` of containers whose launcher is dead, SIGTERM/SIGINT handlers and
an atexit hook -- all of it on the host's docker daemon and in pytest's own
process. Unit tests that drive main() must never do that, so it is stubbed for
every test. The stub records each call's experiment id; a test asks for
``launcher_cleanup_calls`` to check that main() still installs it. A test of
the function itself opts out with @pytest.mark.real_launcher_cleanup and stubs
what it touches.
"""
import pytest


@pytest.fixture(autouse=True)
def launcher_cleanup_calls(request, monkeypatch):
    calls: list = []
    if request.node.get_closest_marker("real_launcher_cleanup"):
        return calls
    import sandbox.session as session
    monkeypatch.setattr(session, "install_launcher_cleanup",
                        lambda experiment_id="": calls.append(experiment_id))
    return calls
