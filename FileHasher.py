import hashlib
import os
import hashlib
from typing import Optional, Callable


class FileHasher:
    """
    A class to generate and validate hashes for files.
    # Example usage
    file_path = 'path_to_your_executable.exe'
    expected_hash = 'your_expected_hash_value'

    hasher = FileHasher('SHA256')

    # Generate the hash
    generated_hash = hasher.generate_hash(file_path)
    print(f'Generated SHA256 Hash: {generated_hash}')

    # Validate the hash
    is_valid = hasher.validate_hash(file_path, expected_hash)
    print(f'Hash validation: {is_valid}')
    """

    def __init__(
        self,
        algorithm: str = "SHA256",
    ):
        """
        Initializes the FileHasher with the desired hashing algorithm.

        Args:
            algorithm (str): The hashing algorithm to use (e.g., 'SHA256', 'SHA1', 'MD5').
        """
        self.algorithm: str = algorithm.upper()
        self.hash_function: Callable[[bytes], hashlib.hash] = getattr(
            hashlib, self.algorithm.lower()
        )

    def generate_hash(self, file_path: str) -> str:
        """
        Generates the hash of a file.

        Args:
            file_path (str): The path to the file.

        Returns:
            str: The hexadecimal hash value.
        """
        hash_obj: hashlib.hash = self.hash_function()
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hash_obj.update(chunk)
        hex_hash: str = hash_obj.hexdigest()
        return hex_hash

    def validate_hash(
        self,
        file_path: str,
        expected_hash: str,
    ) -> bool:
        """
        Validates the hash of a file against an expected hash value.

        Args:
            file_path (str): The path to the file.
            expected_hash (str): The expected hash value.

        Returns:
            bool: True if the hash matches, False otherwise.
        """
        generated_hash: str = self.generate_hash(file_path)
        is_hash_matching: bool = generated_hash == expected_hash
        return is_hash_matching

    def get_example_files_folder_path(
        self,
    ) -> str:
        current_directory: str = os.getcwd()
        images_folder_name: str = "example_files"
        images_folder_path: str = os.path.join(
            current_directory,
            images_folder_name,
        )
        return images_folder_path


def test() -> str:
    algorithm: str = "SHA256"
    filehasher: FileHasher = FileHasher(algorithm=algorithm)
    test_folder_path: str = filehasher.get_example_files_folder_path()

    file_to_hash_name: str = "Nerd123Logo.png"
    file_path: str = os.path.join(
        test_folder_path,
        file_to_hash_name,
    )
    # Generate the hash
    generated_hash: str = filehasher.generate_hash(file_path)
    print(" ")
    print("-" * 40)
    print(f"Generating {algorithm} hash for: {file_to_hash_name}")
    print(f"Generated {algorithm} Hash: {generated_hash}")

    # Validate the hash
    is_valid = filehasher.validate_hash(
        file_path=file_path,
        expected_hash=generated_hash,
    )
    print(f"Hash validation: {is_valid}")
    print("-" * 40)
    # return file_path


# Example usage:
if __name__ == "__main__":
    test()
