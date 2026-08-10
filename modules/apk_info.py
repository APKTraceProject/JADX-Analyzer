import re
import zipfile
import xml.etree.ElementTree as ET
from pathlib import Path


ANDROID_NAMESPACE = (
    "http://schemas.android.com/"
    "apk/res/android"
)


def _find_manifest(
    output_dir: Path
) -> Path:
    """Find AndroidManifest.xml."""

    possible_paths = [
        output_dir
        / "resources"
        / "AndroidManifest.xml",

        output_dir
        / "AndroidManifest.xml"
    ]

    for manifest_path in possible_paths:

        if manifest_path.is_file():
            return manifest_path

    manifests = list(
        output_dir.rglob(
            "AndroidManifest.xml"
        )
    )

    if manifests:
        return manifests[0]

    raise FileNotFoundError(
        "AndroidManifest.xml was not "
        "found in JADX output."
    )


def _get_android_attribute(
    element,
    attribute_name: str
):
    """Get an Android XML attribute."""

    names = [
        (
            f"{{{ANDROID_NAMESPACE}}}"
            f"{attribute_name}"
        ),

        f"android:{attribute_name}",

        attribute_name
    ]

    for name in names:

        value = element.get(name)

        if value is not None:
            return value

    return None


def _convert_number(value):
    """Convert numeric values."""

    if value is None:
        return None

    value = value.strip()

    try:

        if value.lower().startswith(
            "0x"
        ):
            return int(
                value,
                16
            )

        return int(value)

    except ValueError:

        return value


def _get_application_name(
    root
):
    """Get the application name."""

    application = root.find(
        "application"
    )

    if application is None:
        return None

    app_name = (
        _get_android_attribute(
            application,
            "label"
        )
    )

    if app_name is None:
        return None

    # Resource references are resolved later.
    if app_name.startswith("@"):
        return None

    return app_name


def _extract_manifest_info(
    manifest_path: Path
) -> dict:
    """Extract manifest metadata."""

    try:

        tree = ET.parse(
            manifest_path
        )

    except ET.ParseError as error:

        raise ValueError(
            "The decoded manifest "
            "could not be parsed."
        ) from error

    root = tree.getroot()

    return {
        "package_name": (
            root.get("package")
        ),

        "app_name": (
            _get_application_name(
                root
            )
        )
    }


def _get_apk_structure(
    apk_path: Path
) -> dict:
    """Read APK archive information."""

    dex_pattern = re.compile(
        r"^classes(\d*)\.dex$"
    )

    native_pattern = re.compile(
        r"^lib/([^/]+)/([^/]+\.so)$"
    )

    dex_files = []

    native_libraries = []

    supported_abis = set()

    with zipfile.ZipFile(
        apk_path,
        "r"
    ) as apk_file:

        for file_name in apk_file.namelist():

            if dex_pattern.match(
                file_name
            ):

                dex_files.append(
                    file_name
                )

            native_match = (
                native_pattern.match(
                    file_name
                )
            )

            if native_match:

                abi = (
                    native_match.group(1)
                )

                library_name = (
                    native_match.group(2)
                )

                supported_abis.add(
                    abi
                )

                native_libraries.append(
                    {
                        "name": library_name,
                        "abi": abi,
                        "path": file_name
                    }
                )

    dex_files.sort()

    native_libraries.sort(
        key=lambda item: (
            item["abi"],
            item["name"]
        )
    )

    return {
        "dex_count": len(
            dex_files
        ),

        "dex_files": dex_files,

        "is_multidex": (
            len(dex_files) > 1
        ),

        "native_libraries": (
            native_libraries
        ),

        "supported_abis": sorted(
            supported_abis
        )
    }


def get_apk_info(
    config: dict
) -> dict:
    """Extract APK metadata."""

    apk_path = Path(
        config["apk_path"]
    )

    output_dir = Path(
        config["output_dir"]
    )

    if not zipfile.is_zipfile(
        apk_path
    ):

        raise ValueError(
            "The selected file is not "
            "a valid APK archive."
        )

    manifest_path = (
        _find_manifest(
            output_dir
        )
    )

    manifest_info = (
        _extract_manifest_info(
            manifest_path
        )
    )

    apk_structure = (
        _get_apk_structure(
            apk_path
        )
    )

    return {
        "file_name": (
            apk_path.name
        ),

        "file_size_bytes": (
            apk_path.stat().st_size
        ),

        "package_name": (
            manifest_info[
                "package_name"
            ]
        ),

        "app_name": (
            manifest_info[
                "app_name"
            ]
        ),

        "dex_count": (
            apk_structure[
                "dex_count"
            ]
        ),

        "dex_files": (
            apk_structure[
                "dex_files"
            ]
        ),

        "is_multidex": (
            apk_structure[
                "is_multidex"
            ]
        ),

        "native_libraries": (
            apk_structure[
                "native_libraries"
            ]
        ),

        "supported_abis": (
            apk_structure[
                "supported_abis"
            ]
        )
    }