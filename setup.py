from setuptools import setup, find_packages
import os
import re

setup(
        zip_safe = False,
        name = "Dynamic53",
        version = "0.1",
        packages = find_packages(),
        install_requires = ["tornado", "boto >= 2.0b4"],
        entry_points = {
            'console_scripts': [
                'dynamic53 = dynamic53.app:main',
            ]
        },
)

