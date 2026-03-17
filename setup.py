import setuptools

with open("README.md", "r") as fh:
    long_description = fh.read()

setuptools.setup(
    name="python-aidot",
    version="0.3.45",
    author="aidotdev2024",
    url='https://github.com/Aidot-Development-Team/python-aidot',
    description="aidot control wifi lights",
    long_description=long_description,
    long_description_content_type="text/markdown",
    packages=setuptools.find_packages(),
    install_requires=[
        "requests",
        "aiohttp",
    ],
    extras_require={
        # Required for liveType=2 cameras (WebRTC-over-MQTT DataChannel streaming)
        "webrtc": ["aiortc>=1.9.0"],
    },
    classifiers=(
        "Programming Language :: Python :: 3.12",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ),
)