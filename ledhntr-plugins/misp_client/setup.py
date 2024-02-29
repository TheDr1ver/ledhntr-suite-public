from setuptools import setup, find_packages

setup(
    name="misp_client",
    version="1.1",
    author="Nick Driver (@thedr1ver)",
    url="",
    license="Apache License 2.0",
    description="Interact with MISP",
    packages=find_packages(),
    include_package_data=True,
    package_data={'': ['*.conf']},
)