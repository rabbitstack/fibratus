from distutils.core import setup
from distutils.extension import Extension
from Cython.Distutils import build_ext

kstreamc_ext = Extension('kstreamc',
                         ['kstream/kstreamc.pyx'],
                         libraries=["tdh", "advapi32", "ole32"])

setup(
    name="kstreamc",
    version="0.2.0",
    author="Nedim Sabic (RabbitStack)",
    author_email="bhnedo@hotmail.com",
    description="Kernel event stream collector for Fibratus",
    license="Apache",
    keywords="windows kernel, tracing, exploration",
    url="https://github.com/rabbitstack/fibratus",
    classifiers=[
        "Topic :: System",
        "License :: OSI Approved :: Apache License"
    ],
    ext_modules=[kstreamc_ext],
    cmdclass={"build_ext": build_ext}
)
