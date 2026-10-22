from setuptools import setup, find_packages

setup(
    name="blindsight",
    version="0.1.0",
    description="BlindSight: Adversarial Robustness Testing of Digital Forensic Tool Parsers",
    author="Prajwal Chowdary, Dr. Sapna Prasad B Honnavalli",
    author_email="chowdaryprajwal2@gmail.com",
    packages=find_packages(),
    python_requires=">=3.10",
    install_requires=[
        "construct>=2.10",
    ],
    entry_points={
        "console_scripts": [
            "synthforge=synthforge.cli:main",
        ],
    },
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Intended Audience :: Science/Research",
        "Topic :: Security",
        "Programming Language :: Python :: 3",
    ],
)
