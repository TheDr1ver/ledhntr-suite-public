from setuptools import setup, find_packages

setup(
    name="yaml_client",
    version="1.0",
    author="Nick Driver (@thedr1ver)",
    url="",
    license="Apache License 2.0",
    description="Reads and processes YAML-style hunts",
    packages=find_packages(),
    include_package_data=True,
    package_data={'': ['*.conf']},
)