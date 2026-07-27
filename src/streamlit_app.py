import subprocess
import sys
import tempfile
from pathlib import Path

import streamlit as st


PROJECT_ROOT = Path(__file__).resolve().parents[1]
ANALYZER_PATH = PROJECT_ROOT / "src" / "log-analyzer.py"
TEXT_REPORT_PATH = PROJECT_ROOT / "reports" / "analysis-report.txt"
CSV_REPORT_PATH = PROJECT_ROOT / "reports" / "top-attacker-report.csv"
HTML_REPORT_PATH = PROJECT_ROOT / "reports" / "analysis-report.html"


def run_analysis(log_content):

    with tempfile.NamedTemporaryFile(suffix=".log", delete=False) as log_file:
        log_file.write(log_content)
        log_file_path = Path(log_file.name)

    try:
        return subprocess.run(
            [sys.executable, str(ANALYZER_PATH), str(log_file_path)],
            capture_output=True,
            cwd=PROJECT_ROOT,
            text=True
        )
    finally:
        log_file_path.unlink(missing_ok=True)


def read_report(report_path):

    return report_path.read_text(encoding="utf-8")


st.set_page_config(page_title="Log Analyzer", page_icon="🔐", layout="wide")

st.title("Linux Authentication Log Analyzer")
st.write("Upload a Linux authentication log to generate security reports.")

uploaded_log = st.file_uploader(
    "Authentication log file",
    type=["log", "txt"]
)

if uploaded_log is not None:

    if st.button("Analyze log"):

        with st.spinner("Analyzing log file..."):
            analysis_result = run_analysis(uploaded_log.getvalue())

        if analysis_result.returncode != 0:
            st.error("The analyzer could not process this log file.")
            st.code(analysis_result.stderr)
        else:
            text_report = read_report(TEXT_REPORT_PATH)
            csv_report = read_report(CSV_REPORT_PATH)
            html_report = read_report(HTML_REPORT_PATH)

            st.success("Analysis complete")

            st.subheader("Console Report")
            st.code(analysis_result.stdout, language="text")

            st.download_button(
                "Download TXT Report",
                text_report,
                file_name="analysis-report.txt",
                mime="text/plain"
            )

            st.download_button(
                "Download CSV Report",
                csv_report,
                file_name="top-attacker-report.csv",
                mime="text/csv"
            )

            st.subheader("HTML Report")
            st.components.v1.html(html_report, height=900, scrolling=True)
