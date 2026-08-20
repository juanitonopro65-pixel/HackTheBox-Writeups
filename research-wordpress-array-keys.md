# WordPress escapes your values — not your array keys

**Original research · August 2026 · `ju5nxv`**

Every SQL-injection scanner for WordPress rests on one assumption. This note
shows the assumption has a hole, measures it against a real database, and gives
you a detector.

---

## The assumption

WordPress calls `wp_magic_quotes()` on every request. Since PHP dropped magic
quotes in 5.4, WordPress re-implements them itself, so plugin authors keep
getting slash-escaped superglobals whether they want them or not:

```php
// wp-includes/load.php
$_GET    = add_magic_quotes( $_GET );
$_POST   = add_magic_quotes( $_POST );
$_COOKIE = add_magic_quotes( $_COOKIE );
```

The practical consequence is the reason most "obvious" WordPress SQLi is not
exploitable. This looks terrible and is **not** injectable:

```php
$wpdb->query( "UPDATE {$t} SET v = '" . $_POST['x'] . "'" );
```

The quotes in `$_POST['x']` arrive already escaped, so the payload cannot break
out of the string literal. I confirmed this the hard way — I had a candidate
fully verified (latest version, no duplicate, low-privilege reachable) and the
lab refused to reproduce it.

---

## The hole

Look at what `add_magic_quotes()` actually walks:

```php
// wp-includes/functions.php
function add_magic_quotes( $input_array ) {
    foreach ( (array) $input_array as $k => $v ) {
        if ( is_array( $v ) ) {
            $input_array[ $k ] = add_magic_quotes( $v );
        } else {
            $input_array[ $k ] = addslashes( $v );   // <-- the VALUE
        }
    }
    return $input_array;
}
```

`addslashes()` is applied to `$v`. **`$k` is never touched.** Array keys reach
plugin code exactly as the attacker typed them.

---

## Measuring it

Reasoning about escaping chains is how you get things wrong — I had already been
wrong twice this way. So: a WordPress install on MariaDB 11.8, and a
must-use plugin that dumps what actually arrives.

```php
add_action( 'init', function () {
    if ( isset( $_POST['probe'] ) && is_array( $_POST['probe'] ) ) {
        foreach ( $_POST['probe'] as $k => $v ) {
            file_put_contents( '/tmp/probe.txt',
                "KEY   : $k\n  hex : " . bin2hex( $k ) . "\n" .
                "VALUE : $v\n  hex : " . bin2hex( $v ) . "\n" );
        }
    }
} );
```

Sending the same character as both key and value:

```bash
curl -s -o /dev/null -X POST "$SITE/" --data-urlencode "probe[a'b]=c'd"
```

```
KEY   : a'b
  hex : 61 27 62              <- 0x27 is a bare quote. Nothing added.
VALUE : c\'d
  hex : 63 5c 27 64           <- 0x5c backslash inserted before it.
```

Same request, same character, two different outcomes.

---

## Why it matters

The escaping that makes quoted interpolation safe **does not apply to keys**.
So the pattern every scanner treats as harmless is injectable when the tainted
piece is a key:

```php
foreach ( $_POST['fields'] as $id => $value ) {
    $wpdb->get_row( "SELECT * FROM {$t} WHERE field_id = '$id'" );
    //                                                     ^^^^
    //          quoted, and still injectable: $id keeps its quotes
}
```

This inverts the usual triage rule. Normally *quoted* means safe and *unquoted
numeric* means dangerous. For keys, **quoted is dangerous too** — there is no
escaping standing between the attacker and the string literal.

Sanitizing the value does nothing for this. These are all still vulnerable:

```php
foreach ( sanitize_text_field( $_POST['f'] ) as $id => $v ) { ... }  // value only
foreach ( stripslashes_deep( $_POST['f'] ) as $id => $v ) { ... }    // value only
foreach ( wp_unslash( $_POST['f'] ) as $id => $v ) { ... }           // value only
```

`stripslashes_deep()` and `wp_unslash()` are built on `map_deep()`, which — same
as `add_magic_quotes()` — maps over values and leaves keys alone.

---

## The fix

Sanitize the key explicitly, as its own value:

```php
foreach ( $_POST['fields'] as $id => $value ) {
    $id = absint( $id );                      // or sanitize_key() for strings
    $wpdb->get_row( $wpdb->prepare(
        "SELECT * FROM {$t} WHERE field_id = %d", $id
    ) );
}
```

Plenty of plugins already do exactly this. The point is that it has to be
deliberate: nothing in the request pipeline does it for you.

---

## Detecting it at scale

The shape to look for is narrow enough to grep for, and narrow enough that the
false positives are all one of four things:

```
foreach ( <user array> as $KEY => $VALUE )      key comes from the request
    ... $wpdb->...( "... $KEY ..." )            key reaches a query
```

Reject a hit if any of these hold — each cost me a wrong candidate before I
encoded it:

| Not a bug when | Looks like |
|---|---|
| the key is re-assigned sanitized | `$id = absint( $id );` right after `foreach` |
| the query is prepared | `$wpdb->prepare( "... %d", $id )` |
| the key is validated | `in_array( $id, $allowed, true )` |
| the "key" is from another function | file-wide variable matching, not scope-aware |

That last one is worth stressing: analyse **per function scope**. Matching
variables across a whole file produced my most convincing false positives — a
`$key` from a `foreach` on line 4694 "explaining" a query on line 2111.

Run over ~6,000 WordPress plugins (every plugin above 1,000 active installs),
this yields a handful of hits and they are individually reviewable in an
afternoon. The technique is not in any public scanner I know of, because they
all inherit the assumption at the top of this page.

---

## Honest limitations

- The key is **not** a magic bypass — it is one more tainted source. Everything
  else still applies: it has to reach a query, unsanitized, in reachable code.
- Popular plugins mostly handle it correctly. This pays off in code that fewer
  people have audited.
- I have one confirmed instance from that sweep. It is unreported, so it is not
  named here.

---

*Method note: every claim above is measured, not reasoned. The hex dump is from
a live request. The false-positive table is from candidates I opened, read, and
threw away — which is the only reason I trust the ones I kept.*
