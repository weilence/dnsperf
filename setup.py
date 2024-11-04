from setuptools import setup, find_packages

setup(
    name="dnsperf",
    version="0.1.0",
    packages=find_packages(where="src"),
    package_dir={"": "src"},
    install_requires=["click>=8.1.7", "scapy>=2.6.0"],
    entry_points={
        "console_scripts": [
            "dnsperf=dnsperf.main:cli",
        ],
    },
    author="Weilence",
    author_email="weilence@163.com",
    description="A performance testing tool for DNS servers",
    license="MIT",
    url="https://github.com/weilence/dnsperf",
)
