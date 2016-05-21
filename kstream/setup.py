from distutils.core import setup
from distutils.extension import Extension
from Cython.Distutils import build_ext

setup(
    ext_modules=[Extension("kstreamc",
                ["kstreamc.pyx"],
        libraries=["tdh", "advapi32", "ole32"])],
    cmdclass={"build_ext": build_ext}
)
