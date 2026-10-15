from vulnapp.store import connect, find_user, checksum


def test_finds_existing_user():
    assert find_user(connect(), "alice")[0][1] == "alice"


def test_unknown_user_is_empty():
    assert find_user(connect(), "carol") == []


def test_checksum_is_stable():
    assert checksum(b"x") == checksum(b"x")
