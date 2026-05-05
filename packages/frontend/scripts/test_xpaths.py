"""Smoke-test Primus XPaths against checked-in Amazon HTML fixtures.

The Primus attestor parser (per the SDK's own html.test.ts and the runtime
error `[ParseHtmlError][Find] can not find attribute by class,"od-status-..."`)
is a restricted XPath dialect that supports ONLY:

  * step navigation: `//tag`, `tag/child`
  * positional indices: `[N]`
  * exact attribute equality: `[@name="value"]`
  * the `@attr` axis to return an attribute value as a string

It does NOT support: `contains()`, `starts-with()`, `text()`,
`normalize-space()`, `substring*`, or any function inside or outside a
predicate. Plan accordingly.

Fixtures are intentionally local-only because raw Amazon HTML contains user and
order data. Save them as untracked files when you need to smoke-test a template
change.
"""
import sys

import lxml.html
from pathlib import Path


def extract(node) -> str:
    """Mirror what Primus' attestor returns:
    - For an element node: the serialized outer-HTML, with attributes,
      preserving the source whitespace inside but no trailing siblings.
    - For an attribute (string): the attribute value.
    """
    if isinstance(node, str):
        return node
    if hasattr(node, "tag"):
        from lxml import etree
        return etree.tostring(
            node, method="html", encoding="unicode", with_tail=False
        )
    return str(node)


ROOT = Path(__file__).resolve().parents[3]
FRONTEND = Path(__file__).resolve().parent.parent

FIXTURES = []
order_fixture = FRONTEND / "example-order.html"
if order_fixture.exists():
    # Mirror exactly the order-summary template parsePath strings. The Primus
    # parser dialect only accepts id-anchored wildcard descendant, then pure
    # child-axis with every step indexed [N].
    FIXTURES.append(
        (
            order_fixture,
            {
                "shipmentStatus": '//*[@id="shipment-top-row"]/div[1]/div[1]/h4[1]',
                "productTitle": (
                    '//*[@id="orderDetails"]'
                    '/div[1]/div[3]/div[1]/div[1]/div[7]/div[1]/div[1]/div[1]/div[1]'
                    '/div[1]/div[1]/div[1]/div[1]/div[2]/div[1]/div[1]/div[1]/div[2]'
                    '/div[1]/div[1]/div[1]/a[1]'
                ),
                "shipTo": (
                    '//*[@id="orderDetails"]'
                    '/div[1]/div[3]/div[1]/div[1]/div[6]/div[1]/div[1]/div[1]/div[1]'
                    '/div[1]/div[1]/div[1]/div[1]/div[1]/ul[1]'
                ),
                "grandTotal": (
                    '//*[@id="od-subtotals"]'
                    '/div[1]/div[1]/ul[1]/li[6]/span[1]/div[1]/div[2]/span[1]'
                ),
            },
        )
    )

delivery_fixture = next(
    (
        path
        for path in (
            ROOT / "example-delivery.html",
            ROOT / "example.html",
            ROOT / "example-2.html",
        )
        if path.exists()
    ),
    None,
)
if delivery_fixture is not None:
    FIXTURES.append(
        (
            delivery_fixture,
            {
                "deliveryStatus": (
                    '//*[@id="topContent-container"]'
                    '/section[@class="pt-card promise-card"]/h1[1]'
                ),
                "pickupCode": '//*[@id="pickupInformation-container"]/h1[1]',
                "orderId": (
                    '//*[@id="ordersInPackage-container"]'
                    '/div[1]/div[1]/a[1]/@href'
                ),
            },
        )
    )

ok = True
if not FIXTURES:
    print("No local HTML fixtures found; nothing to smoke-test")
    sys.exit(0)

for fixture, xpaths in FIXTURES:
    print(f"fixture: {fixture.relative_to(ROOT)}")
    doc = lxml.html.parse(str(fixture))
    for key, xp in xpaths.items():
        print(f"[{key}]")
        print(f"  xpath:    {xp}")
        try:
            result = doc.xpath(xp)
        except Exception as e:
            print(f"  ERROR:    {e}\n")
            ok = False
            continue

        if isinstance(result, list):
            if not result:
                print("  matched:  0 nodes  (XPath returned empty list)\n")
                ok = False
                continue
            first = result[0]
            text = extract(first)
            printed = " ".join(text.split())
            print(f"  matched:  {len(result)} node(s); showing [0]")
            print(f"  raw_len:  {len(text)}")
            print(f"  text:     {printed!r}")
        else:
            print(f"  scalar:   {result!r}")
        print()

    print()

if ok:
    print("PASS")
else:
    print("FAIL")
    sys.exit(1)
