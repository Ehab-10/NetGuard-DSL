from parser import parse_policy
from model import build_model
from simulator import simulate
from validator import (
    detect_conflicts,
    detect_duplicates,
    detect_missing_dependencies,
    validation_matrix
)


def test_parser_and_model():
    policy = """
    role Students
    network Students 10.10.10.0/24
    network Internet 0.0.0.0/0
    service HTTP tcp 80
    allow Students -> Internet service HTTP
    """

    data = parse_policy(policy)
    model = build_model(data)

    assert "Students" in model["roles"]
    assert model["networks"]["Students"] == "10.10.10.0/24"
    assert model["services"]["HTTP"]["port"] == 80
    assert len(model["rules"]) == 1


def test_simulator_allow():
    policy = """
    role Students
    network Students 10.10.10.0/24
    network Internet 0.0.0.0/0
    service HTTP tcp 80
    allow Students -> Internet service HTTP
    """

    model = build_model(parse_policy(policy))

    assert simulate(model, "Students", "Internet", "HTTP") == "allow"


def test_default_deny():
    policy = """
    role Students
    network Students 10.10.10.0/24
    network Internet 0.0.0.0/0
    service HTTP tcp 80
    """

    model = build_model(parse_policy(policy))

    assert simulate(model, "Students", "Internet", "HTTP") == "deny"


def test_conflict_detection():
    policy = """
    role Students
    network Students 10.10.10.0/24
    network Internet 0.0.0.0/0
    service HTTP tcp 80
    allow Students -> Internet service HTTP
    deny Students -> Internet service HTTP
    """

    model = build_model(parse_policy(policy))

    assert len(detect_conflicts(model)) == 1


def test_duplicate_detection():
    policy = """
    role Students
    network Students 10.10.10.0/24
    network Internet 0.0.0.0/0
    service HTTP tcp 80
    allow Students -> Internet service HTTP
    allow Students -> Internet service HTTP
    """

    model = build_model(parse_policy(policy))

    assert len(detect_duplicates(model)) == 1


def test_missing_dependencies():
    policy = """
    role Students
    network Students 10.10.10.0/24
    network Internet 0.0.0.0/0
    network DNS_Server 10.10.1.10/32
    network DHCP_Server 10.10.1.20/32
    service HTTP tcp 80
    service DNS udp 53
    service DHCP udp 67
    allow Students -> Internet service HTTP
    """

    model = build_model(parse_policy(policy))
    missing = detect_missing_dependencies(model)

    assert len(missing) == 2


def test_validation_matrix_exists():
    policy = """
    role Students
    network Students 10.10.10.0/24
    network Internet 0.0.0.0/0
    service HTTP tcp 80
    allow Students -> Internet service HTTP
    """

    model = build_model(parse_policy(policy))
    matrix = validation_matrix(model)

    assert len(matrix) > 0