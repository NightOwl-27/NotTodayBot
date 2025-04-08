from setuptools import setup
from Cython.Build import cythonize
from setuptools.extension import Extension

setup(
    ext_modules=cythonize([
        Extension(
            name="kitsune_core.AfterImage_extrapolate",  # <--- full module path
            sources=["kitsune_core/AfterImage_extrapolate.pyx"]
        )
    ])
)
