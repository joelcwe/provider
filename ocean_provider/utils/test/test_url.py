#
# Copyright 2021 Ocean Protocol Foundation
# SPDX-License-Identifier: Apache-2.0
#
import logging
from unittest.mock import Mock, patch

import pytest
from ocean_provider.utils.url import (
    get_redirect,
    is_safe_url,
    is_this_same_provider,
    is_url,
)
from requests.models import Response

test_logger = logging.getLogger(__name__)


@pytest.mark.unit
def test_is_url():

    assert is_url("https://jsonplaceholder.typicode.com/") is True
    assert is_url("127.0.0.1") is False
    assert is_url("169.254.169.254") is False
    assert is_url("http://169.254.169.254/latest/meta-data/hostname") is True


@pytest.mark.unit
def test_is_safe_url():
    assert is_safe_url("https://jsonplaceholder.typicode.com/") == (
        True,
        "https://jsonplaceholder.typicode.com/",
    )
    assert is_safe_url("127.0.0.1") == (False, None)
    assert is_safe_url("169.254.169.254") == (False, None)
    assert is_safe_url("http://169.254.169.254/latest/meta-data/hostname") == (
        False,
        None,
    )

    assert is_safe_url("https://bit.ly/3zqzc4m") == (
        True,
        "https://jsonplaceholder.typicode.com/",
    )  # jsonplaceholder example
    assert is_safe_url("https://bit.ly/3znh0Zg") == (
        False,
        None,
    )  # meta-data/hostname example

    assert is_safe_url("blabla") == (False, None)


@pytest.mark.unit
def test_is_same_provider():
    assert is_this_same_provider("http://localhost:8030")


@pytest.mark.unit
def test_get_redirect():
    assert (
        get_redirect("https://bit.ly/3zqzc4m")
        == "https://jsonplaceholder.typicode.com/"
    )

    redirect_response = Mock(spec=Response)
    redirect_response.is_redirect = True
    redirect_response.status_code = 200
    redirect_response.headers = {"Location": "/root-relative.html"}

    normal_response = Mock(spec=Response)
    normal_response.is_redirect = False
    normal_response.status_code = 200

    with patch("ocean_provider.utils.url.requests.head") as mock:
        mock.side_effect = [redirect_response, normal_response]
        assert (
            get_redirect("https://some-url.com:3000/index")
            == "https://some-url.com:3000/root-relative.html"
        )

    redirect_response = Mock(spec=Response)
    redirect_response.is_redirect = True
    redirect_response.status_code = 200
    redirect_response.headers = {"Location": "relative.html"}

    normal_response = Mock(spec=Response)
    normal_response.is_redirect = False
    normal_response.status_code = 200

    with patch("ocean_provider.utils.url.requests.head") as mock:
        mock.side_effect = [redirect_response, normal_response]
        assert (
            get_redirect("https://some-url.com:3000/index")
            == "https://some-url.com:3000/index/relative.html"
        )

    redirect_response = Mock(spec=Response)
    redirect_response.is_redirect = True
    redirect_response.status_code = 200
    redirect_response.headers = {"Location": "https://some-url.com:3000/index"}

    with patch("ocean_provider.utils.url.requests.head") as mock:
        mock.return_value = redirect_response
        assert get_redirect("https://some-url.com:3000/index") is None
        assert mock.call_count == 6

    redirect_response = Mock(spec=Response)
    redirect_response.is_redirect = True
    redirect_response.status_code = 200
    redirect_response.headers = {"Location": "relative.html"}

    normal_response = Mock(spec=Response)
    normal_response.is_redirect = False
    normal_response.status_code = 200

    with patch("ocean_provider.utils.url.requests.get") as mock:
        mock.side_effect = [redirect_response, normal_response]
        assert (
            get_redirect("https://some-url.com:3000/index", file_info_request=True)
            == "https://some-url.com:3000/index/relative.html"
        )
