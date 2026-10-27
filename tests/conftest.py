def pytest_addoption(parser):
    parser.addoption(
        "--html5-entities",
        action="store_true",
        default=False,
        help="Run the exhaustive HTML5 named-entity tests for each parser backend",
    )
