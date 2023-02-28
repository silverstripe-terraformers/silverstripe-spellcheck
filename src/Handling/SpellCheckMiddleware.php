<?php

namespace SilverStripe\SpellCheck\Handling;

use SilverStripe\Dev\Deprecation;
use SilverStripe\Control\HTTPRequest;
use SilverStripe\Control\Middleware\HTTPMiddleware;
use SilverStripe\Core\Config\Configurable;
use SilverStripe\Forms\HTMLEditor\TinyMCEConfig;
use SilverStripe\i18n\i18n;

/**
 * @deprecated 2.0.0 Use SpellCheckAdminExtension instead
 */
class SpellCheckMiddleware implements HTTPMiddleware
{
    use Configurable;

    /**
     * HTMLEditorConfig name to use
     *
     * @var string
     * @config
     */
    private static string $editor = 'cms';

    public function __construct()
    {
        Deprecation::notice('2.0.0', 'Use SpellCheckAdminExtension instead', Deprecation::SCOPE_CLASS);
    }

    public function process(HTTPRequest $request, callable $delegate): callable
    {
        return $delegate($request);
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
