package lab.deploy

import rego.v1

# ---- BLOQUEOS: cualquier elemento de "deny" hace fallar el pipeline ----

deny contains msg if {
	input.container.user in {"", "root", "0"}
	msg := "BLOQUEO: el contenedor se ejecuta como root (falta un USER sin privilegios)"
}

deny contains msg if {
	not contains(input.container.base_image, ":")
	msg := sprintf("BLOQUEO: la imagen base '%v' no tiene etiqueta de version", [input.container.base_image])
}

deny contains msg if {
	endswith(input.container.base_image, ":latest")
	msg := "BLOQUEO: la imagen base usa la etiqueta 'latest' (no reproducible)"
}

deny contains msg if {
	some dep in input.dependencies
	not contains(dep, "==")
	msg := sprintf("BLOQUEO: dependencia sin version fija: %v", [dep])
}

# ---- ADVERTENCIAS: se informan pero NO bloquean ----

warn contains msg if {
	not input.container.healthcheck
	msg := "ADVERTENCIA: la imagen no define HEALTHCHECK"
}
