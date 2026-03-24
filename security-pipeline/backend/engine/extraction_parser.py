"""
Extraction Parser — Stage 2 of the pipeline.
Normalizes multi-source input into plain text for downstream analysis.
"""

import io
import logging
from models.schemas import InputType

logger = logging.getLogger(__name__)


class ExtractionParser:
    """
    Extracts and normalizes text from multiple sources:
    - Raw text / SQL / chat messages
    - PDF files (via PyPDF2)
    - DOC/DOCX files (via python-docx)
    - TXT/LOG files (raw)
    """

    def normalize(self, content: str, input_type: InputType) -> str:
        """
        Normalize text content based on input type.
        For JSON payload requests (text, sql, chat, log), content is already text.
        """
        if input_type in (InputType.TEXT, InputType.SQL, InputType.CHAT, InputType.LOG):
            return content.strip()
        elif input_type == InputType.FILE:
            return content.strip()
        else:
            logger.warning(f"Unknown input_type: {input_type}, treating as raw text")
            return content.strip()

    def extract_from_bytes(self, raw_bytes: bytes, file_ext: str, filename: str = "") -> str:
        """
        Extract text from uploaded file bytes based on extension.
        """
        file_ext = file_ext.lower()

        if file_ext in (".txt", ".log"):
            return self._extract_text(raw_bytes)
        elif file_ext == ".pdf":
            return self._extract_pdf(raw_bytes)
        elif file_ext in (".doc", ".docx"):
            return self._extract_docx(raw_bytes)
        else:
            logger.warning(f"Unsupported extension '{file_ext}' for {filename}, trying as text")
            return self._extract_text(raw_bytes)

    @staticmethod
    def _extract_text(raw_bytes: bytes) -> str:
        """Decode raw bytes as text, trying multiple encodings."""
        for encoding in ("utf-8", "latin-1", "ascii", "cp1252"):
            try:
                return raw_bytes.decode(encoding)
            except (UnicodeDecodeError, LookupError):
                continue
        # Final fallback: lossy decode
        return raw_bytes.decode("utf-8", errors="replace")

    @staticmethod
    def _extract_pdf(raw_bytes: bytes) -> str:
        """Extract text from PDF bytes using PyPDF2."""
        try:
            from PyPDF2 import PdfReader
            reader = PdfReader(io.BytesIO(raw_bytes))
            pages = []
            for page_num, page in enumerate(reader.pages):
                text = page.extract_text()
                if text:
                    pages.append(f"--- Page {page_num + 1} ---\n{text}")
            result = "\n".join(pages)
            logger.info(f"PDF extraction: {len(reader.pages)} pages, {len(result)} chars")
            return result
        except ImportError:
            logger.error("PyPDF2 not installed. Cannot parse PDF files.")
            raise ValueError("PDF parsing requires PyPDF2. Install with: pip install PyPDF2")
        except Exception as e:
            logger.error(f"PDF extraction failed: {e}")
            raise ValueError(f"Failed to extract text from PDF: {e}")

    @staticmethod
    def _extract_docx(raw_bytes: bytes) -> str:
        """Extract text from DOCX bytes using python-docx."""
        try:
            from docx import Document
            doc = Document(io.BytesIO(raw_bytes))
            paragraphs = [p.text for p in doc.paragraphs if p.text.strip()]
            result = "\n".join(paragraphs)
            logger.info(f"DOCX extraction: {len(paragraphs)} paragraphs, {len(result)} chars")
            return result
        except ImportError:
            logger.error("python-docx not installed. Cannot parse DOCX files.")
            raise ValueError("DOCX parsing requires python-docx. Install with: pip install python-docx")
        except Exception as e:
            logger.error(f"DOCX extraction failed: {e}")
            raise ValueError(f"Failed to extract text from DOCX: {e}")