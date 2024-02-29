from setuptools import setup, find_packages

setup(
    name="localfile_client",
    version="1.0",
    author="Nick Driver (@thedr1ver)",
    url="",
    license="Apache License 2.0",
    description="Save files to a local directory",
    packages=find_packages(),
    include_package_data=True,
    package_data={'': ['*.conf']},
)