"""Tests for CLI commands."""

from secimport.cli.main import main


class TestCLIListConnectors:
    def test_list_connectors(self, capsys):
        ret = main(["list-connectors"])
        assert ret == 0
        output = capsys.readouterr().out
        assert "qualys" in output
        assert "crowdstrike_falcon" in output
        assert "splunk" in output

    def test_list_parsers(self, capsys):
        ret = main(["list-parsers"])
        assert ret == 0
        output = capsys.readouterr().out
        assert "qualys" in output.lower()


class TestCLIDetect:
    def test_detect_qualys(self, tmp_path, capsys):
        csv_file = tmp_path / "qualys.csv"
        csv_file.write_text("IP,DNS,QID,Title,Severity,CVSS Base\n10.0.0.1,web01,1234,Test,5,9.8\n")
        ret = main(["detect", str(csv_file)])
        assert ret == 0
        output = capsys.readouterr().out
        assert "qualys" in output.lower()

    def test_detect_file_not_found(self, capsys):
        ret = main(["detect", "/nonexistent/file.csv"])
        assert ret == 1


class TestCLIParse:
    def test_parse_qualys(self, tmp_path, capsys):
        csv_file = tmp_path / "qualys.csv"
        csv_file.write_text("IP,DNS,QID,Title,Severity,CVSS Base\n10.0.0.1,web01,1234,Test,5,9.8\n")
        ret = main(["parse", str(csv_file)])
        assert ret == 0

    def test_parse_file_not_found(self, capsys):
        ret = main(["parse", "/nonexistent/file.csv"])
        assert ret == 1


class TestCLINoArgs:
    def test_no_args(self, capsys):
        ret = main([])
        assert ret == 0
