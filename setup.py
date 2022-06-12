from setuptools import setup, find_packages

setup(
    name="bukit",
    author="Zacharier",
    packages=find_packages(where="src"),
    package_dir={"": "src"},
    entry_points={"console_scripts": ["bukit = bukit:main"]},
)
