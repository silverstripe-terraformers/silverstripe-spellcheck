<?php

namespace SilverStripe\SpellCheck\Handling;

use SilverStripe\Control\Director;
use SilverStripe\Core\Config\Configurable;
use SilverStripe\Core\Extension;
use SilverStripe\Dev\Deprecation;
use SilverStripe\Forms\HTMLEditor\TinyMCEConfig;
use SilverStripe\i18n\i18n;
use SilverStripe\Security\SecurityToken;

/**
 * Update html editor to enable spellcheck
 */
class SpellCheckAdminExtension extends Extension
{
    use Configurable;

    /**
     * HTMLEditorConfig name to use
     *
     * @var string
     * @config
     */
    private static string $editor = 'cms';

    public function init()
    {
        // Set settings (respect deprecated middleware)
        $middlewareConfig = Deprecation::withNoReplacement(function () {
            return SpellCheckMiddleware::config()->get('editor');
        });
        $editor = $middlewareConfig ?: static::config()->get('editor');

        /** @var TinyMCEConfig $editorConfig */
        $editorConfig = TinyMCEConfig::get($editor);

        $editorConfig->enablePlugins('spellchecker');
        $editorConfig->addButtonsToLine(2, 'spellchecker');

        $token = SecurityToken::inst();

        $editorConfig
            ->setOption('spellchecker_rpc_url', Director::absoluteURL($token->addToUrl('spellcheck/')))
            ->setOption('browser_spellcheck', false)
            ->setOption('spellchecker_languages', implode(',', $this->getLanguages()));

        $defaultLocale = $this->getDefaultLocale();
        if ($defaultLocale) {
            $editorConfig->setOption('spellchecker_language', $defaultLocale);
        }
    }

    /**
     * Check languages to set
     *
     * @return string[]
     */
    public function getLanguages(): array
    {
        $languages = [];
        foreach (SpellController::get_locales() as $locale) {
            $localeName = i18n::getData()->localeName($locale);
            // Fix incorrectly spelled Māori language
            $localeName = str_replace('Maori', 'Māori', $localeName ?? '');
            $languages[] = $localeName . '=' . $locale;
        }
        return $languages;
    }

    /**
     * Returns the default locale for TinyMCE. Either via configuration or the first in the list of locales.
     *
     * @return string|false
     */
    public function getDefaultLocale(): string | false
    {
        // Check configuration first
        $defaultLocale = SpellController::config()->get('default_locale');
        if ($defaultLocale) {
            return $defaultLocale;
        }

        // Grab the first one in the list
        $locales = SpellController::get_locales();
        if (empty($locales)) {
            return false;
        }
        return reset($locales);
    }
}
