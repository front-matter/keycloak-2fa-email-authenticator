<#ftl output_format="plainText">
${msg("emailCodeBody", code, ttl)}

<#if magicLink??>
${msg("emailMagicLink", magicLink)}
</#if>