<!-- PROJECT LOGO -->
<br />
<div align="center">

  <h3 align="center">GateKeeper </h3>

  <p align="center">
    A Flask API to Manage User authentication and authorization using Cognito
    <br />
    <br />
    <a href="https://github.com/CodaCrew-Code-Labs/GateKeeper"><strong>Explore the docs »</strong></a>
    <br />
    <br />
    <a href="https://github.com/CodaCrew-Code-Labs/GateKeeper/issues/new?labels=bug&template=bug-report---.md">Report Bug</a>
    ·
    <a href="https://github.com/CodaCrew-Code-Labs/GateKeeper/issues/new?labels=enhancement&template=feature-request---.md">Request Feature</a>
  </p>
</div>


## Table of Contents

- [Project Description](#project-description)
- [Built With](#built-with)
- [Installation Instructions](#installation-instructions)
- [Features](#features)
- [Changelog](#changelog)
- [API Documentation](#api-documentation)
- [License](#license)


## Project Description

Part of Project **CLAWZY**, this open-source toolkit is a focused library for managing and validating JSON Web Tokens (JWT) exclusively with AWS Cognito. It offers seamless integration for Python applications that require secure user authentication, robust token decoding, and specific error handling for Cognito-related JWTs.


## Built With

This section list frameworks/libraries used to bootstrap the project as well as the current status of the package.


#### Repo Info

[![license][license]][license-url]
[![issues-shield][issues-shield]][issues-url]
[![lastcommit-shield][lastcommit-shield]][lastcommit-url] 
[![github-release][github-release]][github-release-url]
[![Pr-request][Pr-request]][Pr-request-url]
[![Repo-size][Repo-size]][Repo-size-url]
[![Forks][Forks]][Forks-url]


#### Library Info

[![Python][Python]][Python-url] 
[![Docker][Docker]][Docker-url] 
[![Flask][Flask]][Flask-url] 
[![Flake8][Flake8]][Flake8-url]
[![Black][Black]][Black-url]  
[![Poetry][Poetry]][Poetry-url]  


#### Last Build Details

[![Github-build][Github-build]][Github-build-url]
[![Codecov][Codecov]][Codecov-url]
[![Codefactor][Codefactor]][Codefactor-url]
[![Codacy][Codacy]][Codacy-url]
[![Scrutinizer][Scrutinizer]][Scrutinizer-url]


#### Supported Platforms

[![Linux][Linux]][Linux-url]
[![Cloud][Cloud]][Cloud-url]


#### Other Apps

* [Snyk](https://app.snyk.io/org/codacrew-code-labs)


## Installation Instructions

### Prerequisites

- **Python 3.13+** should be installed on your system.
- **AWS Cognito** credentials configured for User Management.

1. **Clone the Repository**:

   ```bash
   git clone https://github.com/yourusername/your-flask-app.git
   cd your-flask-app
   ```

2. **Install Prerequisites**:
    
    ```bash
    Install Make
    pip install poetry
    ```

3. **Create a Virtual Environment**:

   ```bash
   pip install poetry
   poetry shell
   ```

4. **Install Dependencies**:

   ```bash
   poetry install
   ```

5. **Set Up Environment Variables**:

   Create a `.env` file in the root directory with the following:

   ```bash
    FLASK_ENV=development
    AWS_ACCESS_KEY_ID=your_aws_access_key
    AWS_SECRET_ACCESS_KEY=your_aws_secret_key
    AWS_SESSION_TOKEN=your_aws_session_token #If accessed via a role
    USER_POOL_ID=cognito_pool_id_from_aws
    AWS_REGION=cognito_pool_region
    GATEKEEPER_CLIENT_ID=congnito_pool_client_id
    JWKS_URL=cognito_pool_jws_url
   ```

7. **Run the Application**:

   ```bash
   make run
   ```

## Features
- **AWS Cognito JWT Decoding and Validation:** Decode and verify AWS Cognito JWTs using the public keys associated with your Cognito user pool.
- **Comprehensive Error Handling:** Captures exceptions such as ExpiredSignatureError and InvalidTokenError, enabling detailed responses and secure handling for expired or malformed tokens.
- **Built-in Caching for Efficiency:** Uses an efficient caching mechanism to store and reuse JWKs, optimizing the token verification process.
- **Part of the Project CLAWZY Ecosystem:** Designed as a core authentication and authorization module, this library powers secure access for applications under Project CLAWZY.

## Changelog

### v1.0.0
- Initial release.
- Basic functionality of authentication / authorizing & validating security tokens for mutli app access using cognito tags

## API Documentation
Yet to add the link

## License

This project is licensed under the MIT License.

<!-- MARKDOWN LINKS & IMAGES -->
<!-- https://www.markdownguide.org/basic-syntax/#reference-style-links -->
[Python]: https://img.shields.io/badge/python-3.13-blue?style=for-the-badge&logo=python&logoColor=yellow
[Python-url]: https://www.python.org/
[Swagger]: https://img.shields.io/badge/swagger-Ready-green?style=for-the-badge&logo=swagger&logoColor=white
[Swagger-url]: https://swagger.io/
[Flask]: https://img.shields.io/badge/flask-3.0.3-black?style=for-the-badge&logo=flask
[Flask-url]: https://flask.palletsprojects.com/
[Black]: https://img.shields.io/badge/code_style-black-black?style=for-the-badge
[Black-url]: https://pypi.org/project/black/
[Flake8]: https://img.shields.io/badge/linter-flake8-yellow?style=for-the-badge
[Flake8-url]: https://flake8.pycqa.org/
[issues-shield]: https://img.shields.io/github/issues/CodaCrew-Code-Labs/GateKeeper.svg?style=for-the-badge
[issues-url]: https://github.com/CodaCrew-Code-Labs/GateKeeper
[lastcommit-shield]: https://img.shields.io/github/last-commit/CodaCrew-Code-Labs/GateKeeper?style=for-the-badge
[lastcommit-url]: https://github.com/CodaCrew-Code-Labs/GateKeeper
[github-release]: https://img.shields.io/github/v/release/CodaCrew-Code-Labs/GateKeeper?style=for-the-badge
[github-release-url]: https://github.com/CodaCrew-Code-Labs/GateKeeper
[license]:https://img.shields.io/badge/license-mit-green?style=for-the-badge
[license-url]:https://github.com/CodaCrew-Code-Labs/GateKeeper/LICENSE
[docker]: https://img.shields.io/badge/docker-enabled-black?style=for-the-badge&logo=docker
[docker-url]: https://www.docker.com/
[Poetry]: https://img.shields.io/badge/dependency_management-poetry-blue?style=for-the-badge&logo=poetry&logoColor=blue
[Poetry-url]: https://python-poetry.org/
[Github-build]: https://img.shields.io/github/actions/workflow/status/CodaCrew-Code-Labs/GateKeeper/code_performance.yml?style=for-the-badge
[Github-build-url]: https://github.com/CodaCrew-Code-Labs/GateKeeper/actions/workflows/flask-build.yml
[Codecov]: https://img.shields.io/codecov/c/gh/CodaCrew-Code-Labs/GateKeeper/dev?token=BhqSN0VMFd&style=for-the-badge
[Codecov-url]: https://github.com/CodaCrew-Code-Labs/GateKeeper
[Pr-request]: https://img.shields.io/github/issues-pr/CodaCrew-Code-Labs/GateKeeper?style=for-the-badge
[Pr-request-url]: https://github.com/CodaCrew-Code-Labs/GateKeeper
[Repo-size]: https://img.shields.io/github/repo-size/CodaCrew-Code-Labs/GateKeeper?style=for-the-badge
[Repo-size-url]: https://github.com/CodaCrew-Code-Labs/GateKeeper
[Forks]: https://img.shields.io/github/forks/CodaCrew-Code-Labs/GateKeeper?style=for-the-badge
[Forks-url]: https://github.com/CodaCrew-Code-Labs/GateKeeper
[Linux]: https://img.shields.io/badge/platform-linux-brightgreen?style=for-the-badge
[Linux-url]: https://www.linux.org/
[Windows]: https://img.shields.io/badge/platform-windows-blue?style=for-the-badge
[Windows-url]:  https://www.microsoft.com/en-us/windows
[MacOS]: https://img.shields.io/badge/platform-macOS-lightgrey?style=for-the-badge
[MacOS-url]:  https://www.apple.com/macos/  
[Cloud]: https://img.shields.io/badge/platform-Cloud-orange?style=for-the-badge
[Cloud-url]: https://aws.amazon.com/cloud/
[Codefactor]: https://img.shields.io/codefactor/grade/github/CodaCrew-Code-Labs/GateKeeper?style=for-the-badge&logo=codefactor&label=CodeFactor
[Codefactor-url]: https://www.codefactor.io/repository/github/codacrew-code-labs/GateKeeper
[Codacy]: https://img.shields.io/codacy/grade/c75aad4375bc416696c80b4553f653b6/dev?style=for-the-badge&logo=codacy&label=Codacy
[Codacy-url]: https://app.codacy.com/gh/CodaCrew-Code-Labs/GateKeeper/dashboard
[Scrutinizer]: https://img.shields.io/scrutinizer/quality/g/CodaCrew-Code-Labs/GateKeeper?style=for-the-badge&label=Scrutinizer%20Code%20Quality
[Scrutinizer-url]: https://scrutinizer-ci.com/g/CodaCrew-Code-Labs/GateKeeper/
