from setuptools import setup
from Cython.Build import cythonize
from setuptools.extension import Extension

extensions = [
    Extension(
        "hash_generator_plus_cython",
        ["hash_generator_plus_cython.pyx"],
        libraries=["crypto"],
        include_dirs=["/usr/include"],
        library_dirs=["/usr/lib"]
    )
]

setup(
    name="hash_generator_plus",
    ext_modules=cythonize(extensions),
    zip_safe=False,
)
