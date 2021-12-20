import setuptools

setuptools.setup(
    name="cdk-security-analytics-bootstrap",
    version="1.0.0",

    description="CDK Security Analytics Bootstrap Project",

    author="author",

    install_requires=[
        "aws-cdk-lib>=2.2.0",
        "constructs>=10.0.0"
    ],

    python_requires=">=3.6",

    classifiers=[
        "Development Status :: 4 - Beta",

        "Intended Audience :: Developers",

        "License :: OSI Approved :: Apache Software License",

        "Programming Language :: JavaScript",
        "Programming Language :: Python :: 3 :: Only",
        "Programming Language :: Python :: 3.6",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",

        "Topic :: Software Development :: Code Generators",
        "Topic :: Utilities",

        "Typing :: Typed",
    ],
)
