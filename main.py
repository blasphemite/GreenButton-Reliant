#!/usr/bin/env python3

import csv
import io
import sys
from datetime import datetime, timedelta
from zipfile import ZipFile

import httpx
import typer
import xmltodict
from dateutil import parser as dateutil
from loguru import logger
from rich import print
from typing_extensions import Annotated


class GreenButton:
    class request:
        headers = {
            "Referrer": "https://my.reliant.com/public/altLogon.htm",
            "Origin": "https://my.reliant.com",
        }
        data = {
            "TEALcookie": "",
            "USER": "",
            "PASSWORD": "",
            "rememberMe": "on",
            "target": "/protected/login.htm",
        }

        def __init__(self, email: str = None, password: str = None):
            self.data["USER"] = email
            self.data["PASSWORD"] = password

    def __init__(self, email, password, populate: bool = False):
        self.client = httpx.Client()
        self.req = self.request(email, password)
        self._logged_in = False

        if populate:
            self.__populate()

    def export_csv(self, save_path: str = "GreenButtonData.csv") -> None:
        if not hasattr(self, "usage"):
            self.__populate()

        with open(save_path, "w", newline="") as f:
            writer = csv.writer(f)
            writer.writerow(["start", "duration_s", "cost"])
            writer.writerows(self.usage)

    def export_zip(self, save_path: str = "GreenButtonData.zip") -> None:
        self.__get_usage_zip(save_zip=True, save_path=save_path)

    def __populate(self) -> None:
        zip_data = self.__get_usage_zip()
        data_dict = self.__dict_from_zip(zip_data)
        usage, entries, xml_created_date = self.__parse_data_dict(data_dict)
        self.usage = usage
        self.last_xml_update = xml_created_date

    def __login(self, force: bool = False) -> None:
        """
        > Login to Reliant
            - force [ bool ]    Force login even if already logged in
        """
        if self._logged_in and not force:
            print("Already logged in; use force=True to re-login")
            return
        r = self.client.post(
            "https://my.reliant.com/siteminderagent/forms/relLogin.fcc",
            data=self.req.data,
            headers=self.req.headers,
            follow_redirects=False,
        )

        while (
            r.status_code != 200
            and r.next_request.url
            != "https://my.reliant.com/protected/primaryCallHandler.htm"
        ):
            match r.next_request.method:
                case "GET":
                    r = self.client.get(r.next_request.url, headers=self.req.headers)
                case "POST":
                    r = self.client.post(r.next_request.url, headers=self.req.headers)

        if (
            r.next_request.url
            != "https://my.reliant.com/protected/primaryCallHandler.htm"
        ):
            raise Exception(f"Login failed ({r.status_code})")

        r = self.client.get(r.next_request.url, headers=self.req.headers, timeout=None)
        self._logged_in = True

    def __get_usage_zip(
        self, login_if_not_already: bool = True, save_zip: bool = False, **kwargs
    ) -> bytes | None:
        """
        > Get the GreenButtonData.zip data
            - login_if_not_already   [ bool ]    Login if not already logged in
            - save_zip               [ bool ]    Save the ZIP archive to disk
            - save_path              [ str ]     Path to save the ZIP archive to

        Returns:
            bytes: ZIP archive data
        """

        if not self._logged_in and login_if_not_already:
            self.__login()

        now = datetime.now()
        timeframe = (now, now - timedelta(hours=1))
        start = timeframe[0].strftime("%m%Y")
        end = timeframe[1].strftime("%m%Y")

        if start.startswith("0"):
            start = start[1:]
        if end.startswith("0"):
            start = end[1:]

        with self.client.stream(
            "GET",
            f"https://my.reliant.com/protected/dashboard/esense/downloadGreenButtonData.htm?languageCode=en_US&startMonthYear={start}&endMonthYear={end}",
            headers=self.req.headers,
        ) as response:
            zip_data = response.read()

        if not save_zip:
            logger.info(f"Returning ZIP data ({len(zip_data)} bytes))")
            return zip_data
        else:
            if "save_path" not in kwargs.keys():
                raise Exception("save_zip=True requires save_path to be specified")

            with open(kwargs["save_path"], "wb") as f:
                f.write(zip_data)
                return

    def __get_data_dict(self, **kwargs) -> dict:
        """
        > Get a dict from the GreenButtonData.zip file

        Returns:
            dict: XML data as a dict
        """
        zip_data = self.__get_usage_zip(**kwargs)
        data_dict = self.__dict_from_zip(zip_data, **kwargs)
        return data_dict

    def __dict_from_zip(
        self, zip: bytes | str, file: bool = False, bytes: bool = True, **kwargs
    ) -> dict:
        """
        > Get a dict from the GreenButtonData.zip file
            - zip     [ bytes|str ]   Archive to read from
            - file    [ bool ]        Input is a file path
            - bytes   [ bool ]        Input is bytes

        Returns:
            dict: XML data as a dict
        """
        if file:
            if "file_path" not in kwargs.keys():
                fp = "GreenButtonData.zip"
            else:
                fp = kwargs["file_path"]

            with open(fp, "rb") as stream:
                zipdata = stream.read()
        elif bytes:
            zipdata = self.__get_usage_zip()
        else:
            raise Exception("Must specify either file or bytes")

        zipf = io.BytesIO(zipdata)

        with ZipFile(zipf) as stream:
            data = stream.read(stream.infolist()[0]).decode("utf-8")
            _dict = xmltodict.parse(data)

        return _dict

    def __parse_data_dict(self, data: dict) -> list:
        """
        > Get a list of usage data from the GreenButtonData.zip file
            - data  [ dict ]   XML data as a dict

        Returns:
            list: Usage data as a list of tuples
        """

        entries = data["ns:feed"]["ns:entry"]

        usage = []
        xml_created_date = dateutil.parse(data["ns:feed"]["ns:updated"])

        for entry in entries:
            title = entry["ns:title"]
            if title is not None:
                print(f"Skipping: {title}")
                continue
            content = entry["ns:content"]
            interval_blocks = content["IntervalBlock"]
            for interval_block in interval_blocks:
                start = interval_block["interval"]["start"]
                # interval = interval_block["interval"]["duration"]
                readings = interval_block["IntervalReading"]
                for reading in readings:
                    time_period = reading["timePeriod"]
                    duration = time_period["duration"]
                    start = datetime.fromtimestamp(int(time_period["start"]))
                    value = reading["value"]
                    usage.append((start, duration, value))

        return [usage, entries, xml_created_date]

    def get_usage_zip(self, **kwargs) -> bytes:
        return self.__get_usage_zip(**kwargs)


def main(
    email: Annotated[str, typer.Option] = typer.Option(
        ..., "--email", "-e", prompt=True, help="Reliant account email"
    ),
    password: Annotated[str, typer.Option] = typer.Option(
        ...,
        "--password",
        "-p",
        prompt=True,
        confirmation_prompt=False,
        hide_input=True,
        help="Reliant account password",
    ),
    save_zip: Annotated[bool, typer.Option] = typer.Option(
        False, "--save-zip", "-sz", help="Export a ZIP archive instead of a CSV"
    ),
    file_path: Annotated[str, typer.Argument] = typer.Argument(
        "GreenButtonData.csv", help="Save path for the output file"
    ),
):
    gb = GreenButton(email, password)

    if save_zip:
        if file_path == "GreenButtonData.csv":
            logger.info("Defaulting to 'GreenButtonData.zip'")
            file_path = "GreenButtonData.zip"
        if not file_path.endswith(".zip"):
            raise Exception("save_zip=True requires file_path to end with .zip")
        gb.export_zip(save_path=file_path)

    gb.export_csv(save_path=file_path)


if __name__ == "__main__":
    logger.remove()
    logger.add(sys.stdout, level="INFO")
    typer.run(main)
