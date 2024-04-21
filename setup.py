from setuptools import Extension, setup

setup(
    ext_modules=[
        Extension(
            name="ntp.c",
            sources=["ntp_c.c"],
        ),
    ]
)
