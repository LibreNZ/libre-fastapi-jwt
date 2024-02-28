<h1 align="left" style="margin-bottom: 20px; font-weight: 500; font-size: 50px; color: black;">
  FastAPI JWT Auth
</h1>

[![Tests](https://github.com/cblgn/fastapi-jwt2/actions/workflows/tests.yml/badge.svg)](https://github.com/cblgn/fastapi-jwt2/actions/workflows/tests.yml)
[![CodeQL](https://github.com/cblgn/fastapi-jwt2/actions/workflows/codeql.yml/badge.svg)](https://github.com/cblgn/fastapi-jwt2/actions/workflows/codeql.yml)
[![PyPI version](https://badge.fury.io/py/fastapi-jwt2.svg)](https://badge.fury.io/py/fastapi-jwt2)
[![Downloads](https://static.pepy.tech/personalized-badge/fastapi-jwt2?period=total&units=international_system&left_color=grey&right_color=brightgreen&left_text=Downloads)](https://pepy.tech/project/fastapi-jwt2)

---
<h3> BTW - The project is based on <a href="https://pypi.org/project/fastapi-jwt2/" target="_blank">Fastapi-jwt-auth</a> that is no longer maintained. </h3> 

**Documentation**: <a href="https://cblgn.github.io/fastapi-jwt2" target="_blank">https://cblgn.github.io/fastapi-jwt2</a>

**Source Code**: <a href="https://github.com/cblgn/fastapi-jwt2" target="_blank">https://github.com/cblgn/fastapi-jwt2</a>

---

## Features
FastAPI extension that provides JWT Auth support (secure, easy to use and lightweight), if you were familiar with flask-jwt-extended this extension suitable for you, cause this extension inspired by flask-jwt-extended 😀

- Access tokens and refresh tokens
- Freshness Tokens
- Revoking Tokens
- Support for WebSocket authorization
- Support for adding custom claims to JSON Web Tokens
- Storing tokens in cookies and CSRF protection

## Installation
The easiest way to start working with this extension with pip

```bash
pip install fastapi-jwt2
```

If you want to use asymmetric (public/private) key signing algorithms, include the <b>asymmetric</b> extra requirements.
```bash
pip install 'fastapi-jwt2[asymmetric]'
```

## License
This project is licensed under the terms of the MIT license.
