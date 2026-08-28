"""Rendered provider-setup regressions for the local Admin UI."""

import pytest
from playwright.sync_api import ConsoleMessage, Page, ViewportSize, expect


def _open_admin(
    page: Page,
    admin_base_url: str,
    viewport: ViewportSize,
) -> None:
    page.set_viewport_size(viewport)
    page.emulate_media(reduced_motion="reduce")
    page.goto(f"{admin_base_url}/admin")
    expect(page.locator("#messageArea")).to_have_text("")


@pytest.mark.parametrize(
    ("viewport", "desktop"),
    (
        ({"width": 1280, "height": 720}, True),
        ({"width": 390, "height": 844}, False),
    ),
)
def test_missing_provider_configuration_scrolls_to_exact_field(
    page: Page,
    admin_base_url: str,
    viewport: ViewportSize,
    desktop: bool,
) -> None:
    _open_admin(page, admin_base_url, viewport)
    card = page.locator('[data-provider="nvidia_nim"]')
    key_input = page.locator("#field-NVIDIA_NIM_API_KEY")

    expect(card.locator(".status-pill")).to_have_text("Missing key")
    expect(card.locator(".provider-meta")).to_have_text("NVIDIA_NIM_API_KEY")
    expect(card.get_by_role("button", name="Configure", exact=True)).to_be_visible()
    expect(card.get_by_role("button", name="Refresh models", exact=True)).to_have_count(
        0
    )
    expect(key_input).not_to_be_in_viewport()

    card.get_by_role("button", name="Configure", exact=True).click()

    expect(key_input).to_be_in_viewport()
    expect(key_input).to_be_focused()
    if desktop:
        sidebar = page.locator(".sidebar")
        expect(sidebar).to_have_css("position", "sticky")
        assert (
            round(
                float(
                    sidebar.evaluate("element => element.getBoundingClientRect().top")
                )
            )
            == 0
        )


def test_configured_provider_check_keeps_readiness_and_adds_models(
    page: Page,
    admin_base_url: str,
) -> None:
    _open_admin(page, admin_base_url, {"width": 1280, "height": 720})
    card = page.locator('[data-provider="open_router"]')
    badge = card.locator(".status-pill")
    meta = card.locator(".provider-meta")

    expect(badge).to_have_text("Configured")
    expect(meta).to_have_text("OPENROUTER_API_KEY")
    expect(card.get_by_role("button", name="Edit", exact=True)).to_be_visible()
    card.get_by_role("button", name="Refresh models", exact=True).click()

    expect(card.locator(".provider-check-result")).to_have_text("2 models available")
    expect(badge).to_have_text("Configured")
    expect(meta).to_have_text("OPENROUTER_API_KEY")

    page.get_by_role("button", name="Model Config", exact=True).click()
    page.get_by_role("button", name="Show Fable Override options", exact=True).click()
    expect(
        page.get_by_role("option", name="open_router/vendor/model-a", exact=True)
    ).to_be_visible()


def test_provider_check_failure_is_separate_and_never_exposes_exception_text(
    page: Page,
    admin_base_url: str,
) -> None:
    console_messages: list[str] = []

    def record_console(message: ConsoleMessage) -> None:
        console_messages.append(message.text)

    page.on("console", record_console)
    _open_admin(page, admin_base_url, {"width": 1280, "height": 720})
    card = page.locator('[data-provider="groq"]')
    card.get_by_role("button", name="Refresh models", exact=True).click()

    result = card.locator(".provider-check-result")
    expect(result).to_have_text(
        "Unavailable: Could not refresh this provider's models. "
        "Verify its configuration and access."
    )
    expect(card.locator(".status-pill")).to_have_text("Configured")
    expect(card.locator(".provider-meta")).to_have_text("GROQ_API_KEY")
    page_text = page.locator("body").inner_text()
    secret = "CREDENTIAL[unrecognized-format-987654321]"
    assert secret not in page_text
    assert "RuntimeError" not in page_text
    assert secret not in "\n".join(console_messages)


def test_multi_field_provider_targets_first_missing_configuration(
    page: Page,
    admin_base_url: str,
) -> None:
    _open_admin(page, admin_base_url, {"width": 1280, "height": 720})
    card = page.locator('[data-provider="cloudflare"]')
    account_input = page.locator("#field-CLOUDFLARE_ACCOUNT_ID")

    expect(card.locator(".status-pill")).to_have_text("Missing configuration")
    expect(card.locator(".provider-meta")).to_have_text(
        "CLOUDFLARE_API_TOKEN + CLOUDFLARE_ACCOUNT_ID"
    )
    expect(account_input).not_to_be_in_viewport()

    card.get_by_role("button", name="Configure", exact=True).click()

    expect(account_input).to_be_in_viewport()
    expect(account_input).to_be_focused()


def _provider_grid_order(page: Page) -> list[str]:
    return page.locator("#providerGrid .provider-card").evaluate_all(
        "cards => cards.map((card) => card.dataset.provider)"
    )


def test_provider_sort_control_orders_by_configuration_and_persists(
    page: Page,
    admin_base_url: str,
) -> None:
    _open_admin(page, admin_base_url, {"width": 1280, "height": 720})
    sort_select = page.locator("#providerSortSelect")

    # (a) Default is catalog order: "nvidia_nim" (missing
    # NVIDIA_NIM_API_KEY, unconfigured) precedes "open_router" (configured
    # via OPENROUTER_API_KEY) in PROVIDER_CATALOG, and the default order
    # preserves that.
    expect(sort_select).to_have_value("catalog")
    catalog_order = _provider_grid_order(page)
    assert catalog_order.index("nvidia_nim") < catalog_order.index("open_router")

    # (b) Selecting "configured-first" moves the configured provider
    # (open_router) ahead of the unconfigured one (nvidia_nim).
    sort_select.select_option("configured-first")
    configured_first_order = _provider_grid_order(page)
    assert configured_first_order.index("open_router") < configured_first_order.index(
        "nvidia_nim"
    )
    # The set of rendered providers is unchanged - only their order moved.
    assert sorted(configured_first_order) == sorted(catalog_order)

    # (c) The choice is persisted in localStorage and survives a reload.
    page.reload()
    expect(page.locator("#messageArea")).to_have_text("")
    expect(sort_select).to_have_value("configured-first")
    reloaded_order = _provider_grid_order(page)
    assert reloaded_order.index("open_router") < reloaded_order.index("nvidia_nim")
