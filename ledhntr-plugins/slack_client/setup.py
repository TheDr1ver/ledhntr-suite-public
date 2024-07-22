from setuptools import setup, find_packages

setup(
    name="slack_client",
    version="1.0",
    author="Nick Driver (@thedr1ver)",
    url="",
    license="Apache License 2.0",
    description="Interact with Slack Workspaces",
    packages=find_packages(),
    include_package_data=True,
    package_data={'': ['*.conf']},
)