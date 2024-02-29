from setuptools import setup, find_packages

setup(
    name="jsonflats_client",
    version="1.0",
    author="Nick Driver (@thedr1ver)",
    url="",
    license="Apache License 2.0",
    description="Track infrastructure in flat JSON files",
    packages=find_packages(),
    include_package_data=True,
    package_data={'': ['*.conf']},
)