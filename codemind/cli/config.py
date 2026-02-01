"""Configuration loader module.

Loads and manages codemind AI configuration.
"""

from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional, Any

import yaml


# Config file names (in priority order)
CONFIG_FILES = [
    ".codemind.yml",
    ".codemind.yaml",
    "codemind.yml",
    "codemind.yaml",
]


@dataclass
class ReviewConfig:
    """Review-specific configuration."""
    max_comments: int = 5
    strict_format: bool = True
    fail_on: list[str] = field(default_factory=lambda: ["security"])


@dataclass
class IDEConfig:
    """IDE-specific configuration."""
    preferred: list[str] = field(default_factory=lambda: ["cursor", "claude-code", "windsurf"])
    auto_inject: bool = True
    auto_submit: bool = False


@dataclass
class PromptConfig:
    """Prompt/template configuration."""
    template_path: Optional[str] = None  # Custom template file path
    extra_rules: list[str] = field(default_factory=list)  # Additional review rules


@dataclass
class RulesConfig:
    """Rules configuration."""
    review_only_diff: bool = True
    allow_feature_suggestions: bool = False


@dataclass  
class Config:
    """Main configuration object."""
    enabled: str = "ask"  # "ask", "always", "never"
    ide: IDEConfig = field(default_factory=IDEConfig)
    review: ReviewConfig = field(default_factory=ReviewConfig)
    rules: RulesConfig = field(default_factory=RulesConfig)
    prompt: PromptConfig = field(default_factory=PromptConfig)
    
    # Internal
    config_path: Optional[Path] = None


class ConfigLoader:
    """Loads configuration from files."""
    
    def __init__(self, start_path: Optional[Path] = None):
        self.start_path = start_path or Path.cwd()
    
    def load(self) -> Config:
        """
        Load configuration, searching up the directory tree.
        
        Returns:
            Config object (defaults if no config found)
        """
        config_path = self._find_config_file()
        
        if config_path is None:
            return Config()
        
        return self._load_from_file(config_path)
    
    def _find_config_file(self) -> Optional[Path]:
        """Search for config file up the directory tree."""
        current = self.start_path.resolve()
        
        while current != current.parent:
            for name in CONFIG_FILES:
                config_path = current / name
                if config_path.exists():
                    return config_path
            current = current.parent
        
        return None
    
    def _load_from_file(self, path: Path) -> Config:
        """Load config from a YAML file."""
        try:
            content = path.read_text(encoding="utf-8")
            data = yaml.safe_load(content) or {}
            
            return self._parse_config(data, path)
        except yaml.YAMLError as e:
            raise ValueError(f"Invalid YAML in {path}: {e}")
    
    def _parse_config(self, data: dict[str, Any], path: Path) -> Config:
        """Parse configuration dictionary."""
        config = Config(config_path=path)
        
        # Top-level settings
        if "enabled" in data:
            config.enabled = str(data["enabled"])
        
        # IDE settings
        if "ide" in data and isinstance(data["ide"], dict):
            ide_data = data["ide"]
            config.ide = IDEConfig(
                preferred=ide_data.get("preferred", config.ide.preferred),
                auto_inject=ide_data.get("auto_inject", config.ide.auto_inject),
                auto_submit=ide_data.get("auto_submit", config.ide.auto_submit),
            )
        
        # Review settings
        if "review" in data and isinstance(data["review"], dict):
            review_data = data["review"]
            config.review = ReviewConfig(
                max_comments=review_data.get("max_comments", config.review.max_comments),
                strict_format=review_data.get("strict_format", config.review.strict_format),
                fail_on=review_data.get("fail_on", config.review.fail_on),
            )
        
        # Rules settings
        if "rules" in data and isinstance(data["rules"], dict):
            rules_data = data["rules"]
            config.rules = RulesConfig(
                review_only_diff=rules_data.get("review_only_diff", config.rules.review_only_diff),
                allow_feature_suggestions=rules_data.get("allow_feature_suggestions", config.rules.allow_feature_suggestions),
            )
        
        # Prompt settings
        if "prompt" in data and isinstance(data["prompt"], dict):
            prompt_data = data["prompt"]
            config.prompt = PromptConfig(
                template_path=prompt_data.get("template_path"),
                extra_rules=prompt_data.get("extra_rules", []),
            )
        
        return config


def load_config(start_path: Optional[Path] = None) -> Config:
    """Convenience function to load configuration."""
    return ConfigLoader(start_path).load()


def get_default_config_content() -> str:
    """Get default configuration file content."""
    return '''# CodeMind Configuration
# See https://github.com/codemind/codemind for documentation

# When to run review: "ask", "always", or "never"
enabled: ask

ide:
  # Preferred IDE order for auto-detection
  preferred:
    - cursor
    - claude-code
    - windsurf
  # Automatically inject prompt into IDE chat
  auto_inject: true
  # Automatically submit prompt (press Enter)
  auto_submit: false

review:
  # Maximum number of comments in review
  max_comments: 5
  # Require strict output format
  strict_format: true
  # Fail push if these issue types are found
  fail_on:
    - security

rules:
  # Only review code in the diff, not entire files
  review_only_diff: true
  # Allow AI to suggest new features
  allow_feature_suggestions: false

prompt:
  # Path to custom prompt template (optional)
  # template_path: ./my-template.txt
  # Additional review rules to include
  extra_rules: []
'''


def get_default_template_content() -> str:
    """Get default prompt template content for users to customize."""
    from ..prompt.builder import DEFAULT_TEMPLATE
    return DEFAULT_TEMPLATE.read_text(encoding="utf-8")

