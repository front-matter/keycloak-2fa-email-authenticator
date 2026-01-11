<html>
<body>
${kcSanitize(msg("emailCodeBody", code, ttl))?no_esc}

<#if magicLink??>
<br/><br/>
<a href="${magicLink?html}">${kcSanitize(msg("emailMagicLink", magicLink))?no_esc}</a>
</#if>
</body>
</html>
