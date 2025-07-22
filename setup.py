import setuptools

with open("README.md", "r") as fh:
    long_description = fh.read()

setuptools.setup(
    name="python-aidot",
    version="0.3.42",
    author="aidotdev2024",
    url='https://github.com/Aidot-Development-Team/python-aidot',
    description="aidot control wifi lights",
    long_description=long_description,
    long_description_content_type="text/markdown",
    packages=setuptools.find_packages(),
    install_requires=[
        "requests",
        "aiohttp",
        "setuptools",
    ],
    classifiers=(
        "Programming Language :: Python :: 3.12",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ),
)