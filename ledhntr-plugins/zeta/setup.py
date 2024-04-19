from setuptools import setup, find_packages

setup(
    name="zeta",
    version="1.0",
    author="Nick Driver (@thedr1ver)",
    url="",
    license="Apache License 2.0",
    description="Interact with Zetalytics API",
    packages=find_packages(),
    include_package_data=True,
    package_data={'': ['*.conf']},
)