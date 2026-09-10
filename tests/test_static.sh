#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

bash -n "$repo_root/single-node/deploy.sh"
bash -n "$repo_root/install.sh"
bash -n "$repo_root/multi-node/tools/create-source-bundle.sh"
"$repo_root/single-node/deploy.sh" --help | grep -q -- "--dry-run"
grep -q "single-node/deploy.sh" "$repo_root/install.sh"
grep -q "github.workflow_sha" "$repo_root/.github/workflows/build-images.yml"

if command -v shellcheck >/dev/null 2>&1; then
	shellcheck "$repo_root/single-node/deploy.sh" "$repo_root/install.sh" "$repo_root/multi-node/tools/create-source-bundle.sh"
fi

python3 - "$repo_root/multi-node/ansible" "$repo_root/single-node/deploy.sh" "$repo_root/install.sh" <<'PY'
import pathlib
import sys

import yaml


class AnsibleLoader(yaml.SafeLoader):
    pass


AnsibleLoader.add_constructor(
    "!vault", lambda loader, node: loader.construct_scalar(node)
)

for path in pathlib.Path(sys.argv[1]).rglob("*.yml"):
    if "templates" in path.parts:
        continue
    yaml.load(path.read_text(encoding="utf-8"), Loader=AnsibleLoader)

playbook_dir = pathlib.Path(sys.argv[1]) / "playbooks"
for name in ("preflight.yml", "relay.yml", "customer.yml", "control.yml", "runtime.yml", "verify.yml"):
    document = yaml.safe_load((playbook_dir / name).read_text(encoding="utf-8"))
    for play in document:
        assert "{{ inventory_dir }}/vault.yml" in play.get("vars_files", []), (
            f"{name} 中的每个 play 都必须加载当前 inventory 的 vault.yml"
        )

for name in ("customer.yml", "control.yml", "runtime.yml"):
    deployment_playbook = yaml.safe_load((playbook_dir / name).read_text(encoding="utf-8"))
    deployment_roles = [
        role
        for play in deployment_playbook
        for role in play.get("roles", [])
    ]
    backup_roles = [
        role
        for role in deployment_roles
        if isinstance(role, dict) and role.get("role") == "deployment_backup"
    ]
    assert backup_roles, f"{name} 必须在发布前执行数据库备份"
    first_backup_index = next(
        index
        for index, role in enumerate(deployment_roles)
        if isinstance(role, dict) and role.get("role") == "deployment_backup"
    )
    first_mutation_index = next(
        index
        for index, role in enumerate(deployment_roles)
        if isinstance(role, dict)
        and role.get("role")
        in {"source_snapshot", "runtime_postgres", "frappe_local_image", "frappe_stack", "python_container"}
    )
    assert first_backup_index < first_mutation_index, f"{name} 必须先备份再修改服务"

deployment_backup_tasks = (
    pathlib.Path(sys.argv[1]) / "roles/deployment_backup/tasks/main.yml"
).read_text(encoding="utf-8")
deployment_backup_manifest = (
    pathlib.Path(sys.argv[1]) / "roles/deployment_backup/templates/manifest.json.j2"
).read_text(encoding="utf-8")
assert "pg_dump" in deployment_backup_tasks
assert "pg_database" in deployment_backup_tasks
assert ".partial" in deployment_backup_tasks
assert "拒绝空的数据库备份" in deployment_backup_tasks
assert "history.jsonl" in deployment_backup_tasks
assert '"release_target"' in deployment_backup_manifest
assert '"running_images"' in deployment_backup_manifest

verify_playbook = (playbook_dir / "verify.yml").read_text(encoding="utf-8")
assert "验证客户 Frappe 到 tBI Engine 的容器网络" in verify_playbook
assert "http://tbi-engine:{{ tbi_engine_port }}/readyz" in verify_playbook

database_playbook = yaml.safe_load((playbook_dir / "database.yml").read_text(encoding="utf-8"))
assert database_playbook[0]["hosts"] == "database_nodes"
assert database_playbook[0]["roles"] == [{"role": "postgresql_host"}]

postgresql_host_tasks = (
    pathlib.Path(sys.argv[1])
    / "roles/postgresql_host/tasks/main.yml"
).read_text(encoding="utf-8")
assert "postgresql-{{ postgresql_host_version }}" in postgresql_host_tasks
assert "postgresql-{{ postgresql_host_version }}-pgvector" in postgresql_host_tasks
assert "listen_addresses = '{{ postgresql_host_listen_addresses }}'" in postgresql_host_tasks
assert "pg_isready" in postgresql_host_tasks

cloudflared_service = (
    pathlib.Path(sys.argv[1])
    / "roles/ingress/templates/cloudflared.service.j2"
).read_text(encoding="utf-8")
assert "--token-file /etc/tai-cloudflared.token" in cloudflared_service
assert "--token ${TUNNEL_TOKEN}" not in cloudflared_service

direct_ingress = (
    pathlib.Path(sys.argv[1]) / "roles/ingress/tasks/direct.yml"
).read_text(encoding="utf-8")
direct_caddyfile = (
    pathlib.Path(sys.argv[1]) / "roles/ingress/templates/direct.Caddyfile.j2"
).read_text(encoding="utf-8")
assert "name: caddy" in direct_ingress
assert "validate: caddy validate" in direct_ingress
assert "reverse_proxy {{ ingress_local_url }}" in direct_caddyfile

runtime_playbook = (playbook_dir / "runtime.yml").read_text(encoding="utf-8")
assert "else 'tai-runtime-postgres'" in runtime_playbook
assert "/{{ runtime_database_name }}" in runtime_playbook
assert "@host.docker.internal:{{ runtime_database_port }}/" not in runtime_playbook
assert "role: embedding" not in runtime_playbook
assert "TAI_RUNTIME_WORKER_DATABASE_URL" in runtime_playbook
assert "python_container_worker_command:" in runtime_playbook

inventory_vars = (
    pathlib.Path(sys.argv[1])
    / "inventories/internal-demo/group_vars/all.yml"
).read_text(encoding="utf-8")
assert "control_database_name: tai_control" in inventory_vars
assert "control_database_user: tai_control_app" in inventory_vars
assert "customer_database_name: tai" in inventory_vars
assert "customer_database_user: tai_app" in inventory_vars
assert "runtime_database_name: tai_service" in inventory_vars

ruisu_inventory_vars = (
    pathlib.Path(sys.argv[1])
    / "inventories/ruisu-customer/group_vars/all.yml"
).read_text(encoding="utf-8")
assert "customer_database_name: tai" in ruisu_inventory_vars
assert "customer_database_user: tai_app" in ruisu_inventory_vars
assert 'customer_control_client_id: ""' in ruisu_inventory_vars
assert 'customer_control_client_secret: ""' in ruisu_inventory_vars
assert 'deployment_http_proxy: "{{ vault_external_deployment_http_proxy | default(\'\') }}"' in ruisu_inventory_vars
assert "deployment_proxy_propagate_to_containers: false" in ruisu_inventory_vars
ruisu_vault_example = (
    pathlib.Path(sys.argv[1])
    / "inventories/ruisu-customer/vault.example.yml"
).read_text(encoding="utf-8")
assert 'vault_external_deployment_http_proxy: ""' in ruisu_vault_example

internal_inventory_vars = (
    pathlib.Path(sys.argv[1])
    / "inventories/internal-demo/group_vars/all.yml"
).read_text(encoding="utf-8")
assert "deployment_http_proxy: http://192.168.2.254:1082" in internal_inventory_vars
assert "deployment_proxy_propagate_to_containers: false" in internal_inventory_vars

docker_tasks = yaml.safe_load(
    (pathlib.Path(sys.argv[1]) / "roles/docker/tasks/main.yml").read_text(encoding="utf-8")
)
daemon_proxy_task = next(task for task in docker_tasks if task["name"] == "写入 Docker Daemon 代理")
assert daemon_proxy_task["ansible.builtin.template"]["mode"] == "0600"
assert daemon_proxy_task["no_log"] is True
container_proxy_task = next(task for task in docker_tasks if task["name"] == "写入 Docker Build 与容器代理")
assert container_proxy_task["when"] == "deployment_proxy_propagate_to_containers | default(false) | bool"
assert container_proxy_task["no_log"] is True
remove_legacy_proxy_task = next(task for task in docker_tasks if task["name"] == "移除 Docker Client 配置中的旧代理")
assert "jq 'del(.proxies)'" in remove_legacy_proxy_task["ansible.builtin.shell"]["cmd"]
assert remove_legacy_proxy_task["changed_when"] == "docker_client_proxy_cleanup.stdout == 'removed'"

tai_service_config = (
    pathlib.Path(sys.argv[1])
    / "roles/tai_service_config/templates/config.json.j2"
).read_text(encoding="utf-8")
assert '"executionMode"' not in tai_service_config
assert '"runtimeStoreId": {{ tai_runtime_store_id | to_json }}' in tai_service_config
assert '"runtimeStoreSecretFile": "/run/secrets/tai_runtime_store_secret"' in tai_service_config
assert '"runtimeStoreUrl"' not in tai_service_config
assert '"harnessStoreUrl"' not in tai_service_config
assert '"memoryStoreUrl"' not in tai_service_config
assert '"issuer": "https://{{ control_site_name }}"' in tai_service_config
assert '"collectorEndpoint": "{{ phoenix_internal_base_url }}/v1/traces"' in tai_service_config
assert "python_container_extra_hosts:" in runtime_playbook

python_container_compose = (
    pathlib.Path(sys.argv[1])
    / "roles/python_container/templates/compose.yml.j2"
).read_text(encoding="utf-8")
assert "python_container_worker_command" in python_container_compose
assert "  worker:" in python_container_compose
assert "      - .env.worker" in python_container_compose
assert "TAI_RUNTIME_WORKER_DATABASE_URL" not in runtime_playbook.split(
    "python_container_worker_environment:", 1
)[0]
assert "TAI_RUNTIME_WORKER_DATABASE_URL" in runtime_playbook.split(
    "python_container_worker_environment:", 1
)[1]
assert "tai_service.durable_cutover --expire-overdue" in runtime_playbook
assert "TAI_RUNTIME_MIGRATION_DATABASE_URL" in runtime_playbook
worker_env_template = (
    pathlib.Path(sys.argv[1])
    / "roles/python_container/templates/worker-env.j2"
).read_text(encoding="utf-8")
assert "python_container_worker_environment.items()" in worker_env_template
python_container_tasks = (
    pathlib.Path(sys.argv[1]) / "roles/python_container/tasks/main.yml"
).read_text(encoding="utf-8")
assert "执行 Python 容器迁移前门禁" in python_container_tasks
assert "python_container_pre_migrate_environment" in python_container_tasks
assert "run --rm -e TAI_RUNTIME_MIGRATION_DATABASE_URL service" in python_container_tasks

preflight_tasks = yaml.safe_load(
    (
        pathlib.Path(sys.argv[1]) / "roles/preflight/tasks/main.yml"
    ).read_text(encoding="utf-8")
)
locked_runtime_release = next(
    task
    for task in preflight_tasks
    if task["name"] == "校验已锁定的 TAI Service 正式版本"
)
locked_runtime_checks = locked_runtime_release["ansible.builtin.assert"]["that"]
assert "tai_service_release_version is match('^[0-9]+\\\\.[0-9]+\\\\.[0-9]+$')" in locked_runtime_checks
assert "tai_service_source_commit is match('^[0-9a-f]{40}$')" in locked_runtime_checks
assert any("tai-service@sha256" in check for check in locked_runtime_checks)
assert "tai_service_release_lock | default(false) | bool" in locked_runtime_release["when"]

runtime_bootstrap_tasks = yaml.safe_load(
    (
        pathlib.Path(sys.argv[1])
        / "roles/tai_service_runtime_bootstrap/tasks/main.yml"
    ).read_text(encoding="utf-8")
)
runtime_bootstrap_names = [task["name"] for task in runtime_bootstrap_tasks]
assert runtime_bootstrap_names == ["等待 TAI Service 就绪"]
runtime_readiness = runtime_bootstrap_tasks[0]
assert runtime_readiness["ansible.builtin.uri"]["url"] == (
    "http://127.0.0.1:{{ tai_service_port }}/readyz"
)
assert runtime_readiness["retries"] >= 10
assert runtime_readiness["until"] == "tai_service_readiness.status == 200"

control_playbook = (playbook_dir / "control.yml").read_text(encoding="utf-8")
assert "frappe_bind_addresses:" in control_playbook
assert '- "{{ ansible_host }}"' in control_playbook
assert "role: tai_control_config" in control_playbook
assert "tai_control_usage:" in control_playbook
assert "tai_runtime_store_secret:" in control_playbook
assert "tai_runtime_store_secret:" in runtime_playbook

control_document = yaml.safe_load(control_playbook)
control_roles = control_document[0]["roles"]
control_image_role = next(
    role for role in control_roles if isinstance(role, dict) and role.get("role") == "frappe_local_image"
)
control_stack_role = next(
    role for role in control_roles if isinstance(role, dict) and role.get("role") == "frappe_stack"
)
assert {"frappe_ext", "tbi", "tai", "tai_control"}.issubset(
    set(control_image_role["vars"]["frappe_local_apps"])
), "控制面会话审计复用 tAI 前端，因此控制镜像必须构建 tAI 及其依赖的静态资源"
assert control_stack_role["vars"]["frappe_apps"] == ["tai_control"], (
    "控制站点只安装 tai_control；tAI、tBI 和 frappe_ext 仅用于构建审计前端资源"
)
assert 'tai_service_token: "{{ vault_tai_service_token }}"' in control_playbook
assert "tai_service_token_file: /run/secrets/tai_service_token" in control_playbook

control_config_tasks = (
    pathlib.Path(sys.argv[1])
    / "roles/tai_control_config/tasks/main.yml"
).read_text(encoding="utf-8")
assert "CREATE EXTENSION IF NOT EXISTS vector" in control_config_tasks
assert "tai_control.vector_store.ensure_runtime_vector_store" in control_config_tasks
assert "tai_control.install.ensure_bootstrap_tenant_from_files" in control_config_tasks
assert "tai_control_client_secret:" in control_playbook

control_settings_script = (
    pathlib.Path(sys.argv[1])
    / "roles/tai_control_config/templates/configure_settings.py.j2"
).read_text(encoding="utf-8")
assert '"issuer"' not in control_settings_script
assert '"audience"' not in control_settings_script
assert '"embedding_enabled"' not in control_settings_script
assert '"agent_runtime_url": "https://{{ runtime_public_hostname }}"' in control_settings_script
assert "frappe.db.set_single_value" in control_settings_script
assert '"chat_provider_key"' not in control_settings_script
assert '"chat_model_key"' not in control_settings_script

customer_playbook = (playbook_dir / "customer.yml").read_text(encoding="utf-8")
assert "'/run/secrets/tai_control_client_secret'" in customer_playbook
assert "customer_control_client_id | default(vault_tai_control_client_id)" in customer_playbook
assert "customer_control_client_secret | default(vault_tai_control_client_secret)" in customer_playbook
assert 'tai_auth_url: "https://{{ auth_public_hostname }}"' in customer_playbook
assert "tai_auth_mode" not in customer_playbook
assert "python_container_install_mssql_driver: true" in customer_playbook
assert 'tbi_engine_base_url: "http://tbi-engine:{{ tbi_engine_port }}"' in customer_playbook
assert "python_container_network_aliases:" in customer_playbook
assert "role: benchmark_project" in customer_playbook
assert "role: benchmark_knowledge" in customer_playbook
assert "role: benchmark_agent" in customer_playbook

benchmark_project_script = (
    pathlib.Path(sys.argv[1])
    / "roles/benchmark_project/templates/bootstrap_project.py.j2"
).read_text(encoding="utf-8")
assert "import_project_mdl" in benchmark_project_script
assert "publish_project" in benchmark_project_script
assert 'service_url + "/v1/projects/register"' in benchmark_project_script
assert "settings.auth_edge_url = auth_url" in benchmark_project_script
assert "settings.auth_mode" not in benchmark_project_script
assert "tai_control.api.auth.register_project" not in benchmark_project_script
assert "initialize_tenant_binding" in benchmark_project_script
assert "benchmark_project_members" in benchmark_project_script
assert 'project.append("members", {"user": member})' in benchmark_project_script

benchmark_knowledge_script = (
    pathlib.Path(sys.argv[1])
    / "roles/benchmark_knowledge/templates/bootstrap_knowledge.py.j2"
).read_text(encoding="utf-8")
assert "publish_runtime_knowledge_release" in benchmark_knowledge_script
assert "retrieve_runtime_knowledge_context" in benchmark_knowledge_script

benchmark_knowledge_tasks = (
    pathlib.Path(sys.argv[1])
    / "roles/benchmark_knowledge/tasks/main.yml"
).read_text(encoding="utf-8")
assert "规范化容器内 Benchmark Knowledge 读取权限" in benchmark_knowledge_tasks
assert "a+rX" in benchmark_knowledge_tasks

benchmark_agent_script = (
    pathlib.Path(sys.argv[1])
    / "roles/benchmark_agent/templates/bootstrap_agent.py.j2"
).read_text(encoding="utf-8")
assert "publish_agent_draft" in benchmark_agent_script
assert "activate_agent_release" in benchmark_agent_script
assert '"agent_key": "data_qa"' in benchmark_agent_script
assert '"kind": "ask_router"' in benchmark_agent_script
assert '"name": "semantic_query"' in benchmark_agent_script

frappe_compose = (
    pathlib.Path(sys.argv[1])
    / "roles/frappe_stack/templates/compose.generated.yml.j2"
).read_text(encoding="utf-8")
assert "for address in frappe_bind_addresses" in frappe_compose
assert "image: {{ frappe_redis_image | to_json }}" in frappe_compose
assert "restart: unless-stopped" in frappe_compose
assert "tai.deploy.secrets-checksum" in frappe_compose
assert "deployment_no_proxy" in frappe_compose

frappe_stack_tasks = (
    pathlib.Path(sys.argv[1])
    / "roles/frappe_stack/tasks/main.yml"
).read_text(encoding="utf-8")
assert "'Recreated' in (frappe_compose_up.stdout ~ frappe_compose_up.stderr)" in frappe_stack_tasks
assert "notify: 刷新 Frappe frontend 上游解析" in frappe_stack_tasks

frappe_stack_document = yaml.safe_load(frappe_stack_tasks)
frappe_stack_task_names = [task["name"] for task in frappe_stack_document]
inspect_legacy_source = frappe_stack_task_names.index("检查 frappe_docker Git 元数据")
remove_legacy_source = frappe_stack_task_names.index("清理本地快照模式遗留的 frappe_docker")
sync_registry_source = frappe_stack_task_names.index("从 Git 仓库同步 frappe_docker")
assert inspect_legacy_source < remove_legacy_source < sync_registry_source
legacy_source_cleanup = frappe_stack_document[remove_legacy_source]
assert legacy_source_cleanup["ansible.builtin.file"]["state"] == "absent"
assert legacy_source_cleanup["when"] == [
    "image_delivery_mode == 'registry'",
    "not frappe_docker_git_metadata.stat.exists",
]
registry_source_sync = frappe_stack_document[sync_registry_source]
assert registry_source_sync["ansible.builtin.git"]["depth"] == 1
assert registry_source_sync["ansible.builtin.git"]["single_branch"] is True
assert registry_source_sync["retries"] == 3
assert registry_source_sync["environment"] == {
    "http_proxy": "{{ deployment_http_proxy | default('') }}",
    "https_proxy": "{{ deployment_http_proxy | default('') }}",
    "no_proxy": "{{ deployment_no_proxy | default('') }}",
    "GIT_CONFIG_COUNT": "1",
    "GIT_CONFIG_KEY_0": "http.proxyAuthMethod",
    "GIT_CONFIG_VALUE_0": "basic",
}

frappe_stack_handlers = (
    pathlib.Path(sys.argv[1])
    / "roles/frappe_stack/handlers/main.yml"
).read_text(encoding="utf-8")
assert "name: 刷新 Frappe frontend 上游解析" in frappe_stack_handlers
assert "restart frontend" in frappe_stack_handlers

frappe_local_image_tasks = (
    pathlib.Path(sys.argv[1])
    / "roles/frappe_local_image/tasks/main.yml"
).read_text(encoding="utf-8")
assert "frappe_local_image_expected_apps" in frappe_local_image_tasks
assert "frappe_local_image_current_apps" in frappe_local_image_tasks
assert "frappe_local_image_requires_build" in frappe_local_image_tasks
assert 'tai.local-apps={{ frappe_local_image_expected_apps }}' in frappe_local_image_tasks

internal_demo_vars = (
    pathlib.Path(sys.argv[1])
    / "inventories/internal-demo/group_vars/all.yml"
).read_text(encoding="utf-8")
assert "tbi-engine" in internal_demo_vars
assert "benchmark_project_members:" in internal_demo_vars
assert "adam.wu@trinfo.net" in internal_demo_vars
assert 'frp_vhost_http_port: 8080' in internal_demo_vars
assert "frp_caddy_email:" in internal_demo_vars

relay_playbook = (playbook_dir / "relay.yml").read_text(encoding="utf-8")
assert "hosts: relay_nodes" in relay_playbook
assert "role: frp_server" in relay_playbook

frp_server_tasks = (
    pathlib.Path(sys.argv[1])
    / "roles/frp_server/tasks/main.yml"
).read_text(encoding="utf-8")
assert "安装 Caddy" in frp_server_tasks
assert "校验 FRP Server 配置" in frp_server_tasks
assert 'src: "{{ frp_server_archive_path }}"' in frp_server_tasks

frps_config = (
    pathlib.Path(sys.argv[1])
    / "roles/frp_server/templates/frps.toml.j2"
).read_text(encoding="utf-8")
assert 'proxyBindAddr = "127.0.0.1"' in frps_config
assert 'transport.tls.force = true' in frps_config
assert 'auth.token = "{{ vault_frp_auth_token }}"' in frps_config

caddy_config = (
    pathlib.Path(sys.argv[1])
    / "roles/frp_server/templates/Caddyfile.j2"
).read_text(encoding="utf-8")
assert "frp_public_hostnames | join(', ')" in caddy_config
assert "reverse_proxy 127.0.0.1:{{ frp_vhost_http_port }}" in caddy_config

preflight_tasks = (
    pathlib.Path(sys.argv[1])
    / "roles/preflight/tasks/main.yml"
).read_text(encoding="utf-8")
assert "relay_nodes" in preflight_tasks
assert "frp_caddy_email" in preflight_tasks
assert "校验中转机基础容量" in preflight_tasks

verify_playbook = (playbook_dir / "verify.yml").read_text(encoding="utf-8")
assert "验证公网中转入口" in verify_playbook
assert "tai-frps" in verify_playbook

python_container_dockerfile = (
    pathlib.Path(sys.argv[1])
    / "roles/python_container/templates/Dockerfile.j2"
).read_text(encoding="utf-8")
assert "packages-microsoft-prod.deb" in python_container_dockerfile
assert "msodbcsql18" in python_container_dockerfile

python_container_compose = (
    pathlib.Path(sys.argv[1])
    / "roles/python_container/templates/compose.yml.j2"
).read_text(encoding="utf-8")
assert "python_container_network_aliases" in python_container_compose

deploy_script = pathlib.Path(sys.argv[2]).read_text(encoding="utf-8")
install_script = pathlib.Path(sys.argv[3]).read_text(encoding="utf-8")
assert 'DEFAULT_DEPLOY_DIR="/opt/tsuite-deploy"' in deploy_script
assert '复用已有 PostgreSQL 部署方式：$DB_MODE' in deploy_script
assert '"$EXISTING_DB_MODE" =~ ^(container|local|adopt)$' in deploy_script
assert 'LEGACY_DEPLOY_DIR="/opt/tsuie-deploy"' in deploy_script
assert "migrate_legacy_deployment" in deploy_script
assert 'mv "$LEGACY_DEPLOY_DIR" "$DEFAULT_DEPLOY_DIR"' in deploy_script
assert "旧部署目录和新部署目录同时存在" in deploy_script
assert "BEGIN tsuie_deploy" in deploy_script
assert "BEGIN tsuite_deploy" in deploy_script
assert "backup_postgres_with_compatible_client" in deploy_script
assert "SHOW server_version_num;" in deploy_script
assert '"postgres:$server_major"' in deploy_script
assert '--volumes-from "$backend_id"' in deploy_script
assert 'backend_network="$(docker inspect' in deploy_script
assert '--network "$backend_network"' in deploy_script
assert '--network "container:$backend_id" --add-host' not in deploy_script
assert 'TSUITE_DEPLOY_REF:-${TSUIE_DEPLOY_REF:-$DEFAULT_REF}' in install_script
assert 'DEFAULT_INSTALL_PATH="/usr/local/sbin/tsuite-deploy"' in install_script

common_tasks = yaml.safe_load(
    (pathlib.Path(sys.argv[1]) / "roles/common/tasks/main.yml").read_text(encoding="utf-8")
)
assert any(task["name"] == "迁移旧版部署目录" for task in common_tasks)
assert any(task["name"] == "迁移旧版 APT 代理配置" for task in common_tasks)

assert any(task["name"] == "迁移旧版 Docker 代理配置" for task in docker_tasks)
PY

fixture_dir="$(mktemp -d /tmp/tsuite-deploy-test.XXXXXX)"
trap 'rm -rf -- "$fixture_dir"' EXIT

# 载入函数但不执行脚本入口，验证生成文件可以被 YAML 解析。
# shellcheck disable=SC1090
source <(sed '$d' "$repo_root/single-node/deploy.sh")
export DEPLOY_DIR="$fixture_dir"
export IMAGE_REPOSITORY="ghcr.io/transinfosh/project_management"
export IMAGE_TAG="test"
export DB_PASSWORD="1234567890abcdef"
export HTTP_PORT="8080"
export DB_MODE="container"
export DB_PORT="5432"
export DB_ADMIN_USER="postgres"
export BIND_ADDRESS="127.0.0.1"
export DOCKER_SUBNET="172.30.0.0/24"
export PROXY_ENABLED=false
export SITE_NAME="project.localhost"
export FRAPPE_DOCKER_COMMIT="test"
# 由动态载入的 write_state 使用。
# shellcheck disable=SC2034
APP_LIST=(project_management)

write_env_file
write_generated_compose
write_proxy_compose
write_state

python3 - "$fixture_dir/compose.generated.yaml" <<'PY'
import sys

import yaml

with open(sys.argv[1], encoding="utf-8") as compose_file:
    document = yaml.safe_load(compose_file)

assert document["services"]["frontend"]["ports"] == ["127.0.0.1:8080:8080"]
assert document["services"]["configurator"]["environment"]["DB_HOST"] == "db"
assert document["networks"]["default"]["ipam"]["config"][0]["subnet"] == "172.30.0.0/24"
PY

grep -q '^CUSTOM_IMAGE=ghcr.io/transinfosh/project_management$' "$fixture_dir/.env"
grep -q '^PULL_POLICY=missing$' "$fixture_dir/.env"
grep -q '^STATE_DB_MODE=container$' "$fixture_dir/deployment.state"
grep -q '^STATE_IMAGE=ghcr.io/transinfosh/project_management:test$' "$fixture_dir/deployment.state"
grep -q '^STATE_FRAPPE_DOCKER_COMMIT=test$' "$fixture_dir/deployment.state"

EXISTING_DEPLOYMENT=false
PREVIOUS_IMAGE=""
PREVIOUS_FRAPPE_DOCKER_COMMIT=""
EXISTING_DB_PASSWORD=""
load_existing_deployment >/dev/null
"$EXISTING_DEPLOYMENT"
[[ "$PREVIOUS_IMAGE" == "ghcr.io/transinfosh/project_management:test" ]]
[[ "$PREVIOUS_FRAPPE_DOCKER_COMMIT" == "test" ]]
[[ "$EXISTING_DB_PASSWORD" == "1234567890abcdef" ]]

export DRY_RUN=false
create_upgrade_snapshot
[[ -f "$ROLLBACK_DIR/.env" ]]
[[ -f "$ROLLBACK_DIR/deployment.state" ]]
[[ "$(cat "$ROLLBACK_DIR/frappe_docker.commit")" == "test" ]]

validate_private_subnet "172.30.0.0/24"
if validate_private_subnet "172.30.0.1/24"; then
	echo "未拒绝非网络地址的 Docker 子网" >&2
	exit 1
fi
if validate_private_subnet "8.8.8.0/24"; then
	echo "未拒绝公网 Docker 子网" >&2
	exit 1
fi

database_password_is_valid "postgres"
if database_password_is_valid ""; then
	echo "错误地接受了空数据库密码" >&2
	exit 1
fi
prompt_database_password RETRIED_PASSWORD "测试数据库密码" "" \
	<<< $'\npostgres' >/dev/null 2>&1
[[ "$RETRIED_PASSWORD" == "postgres" ]]

# 已部署状态代表最后一次成功部署；deployment.inputs 代表上次确认但未完成的尝试。
# 重试时后者必须优先作为交互默认值。
IMAGE="ghcr.io/transinfosh/srm:0.1.8"
APP_LIST=(srm)
SITE_NAME="srm.dtaut.com"
BIND_ADDRESS="0.0.0.0"
HTTP_PORT="9080"
FRAPPE_DOCKER_REPO="https://github.com/example/frappe_docker.git"
FRAPPE_DOCKER_REF="release-candidate"
DOCKER_SUBNET="172.31.0.0/24"
DB_MODE="local"
DB_PORT="5433"
DB_ADMIN_USER="frappe_admin"
write_deployment_inputs

# shellcheck disable=SC2317 # 由动态载入的 collect_deployment_settings 间接调用。
prompt() {
	local variable_name="$1"
	local default_value="${3:-}"
	if [[ "$variable_name" == "DEPLOY_DIR" ]]; then
		printf -v "$variable_name" '%s' "$fixture_dir"
	else
		printf -v "$variable_name" '%s' "$default_value"
	fi
}
confirm() {
	return 1
}
EXISTING_DEPLOYMENT=false
collect_deployment_settings >/dev/null
[[ "$IMAGE" == "ghcr.io/transinfosh/srm:0.1.8" ]]
[[ "${APP_LIST[*]}" == "srm" ]]
[[ "$SITE_NAME" == "srm.dtaut.com" ]]
[[ "$BIND_ADDRESS" == "0.0.0.0" ]]
[[ "$HTTP_PORT" == "9080" ]]
[[ "$FRAPPE_DOCKER_REPO" == "https://github.com/example/frappe_docker.git" ]]
[[ "$FRAPPE_DOCKER_REF" == "release-candidate" ]]
[[ "$DOCKER_SUBNET" == "172.31.0.0/24" ]]
[[ "$DB_MODE" == "container" ]]

# GHCR 首次手工登录后应保存 root-only 凭据；下一次拉取应先用保存的凭据，
# 无需再次执行交互输入。
GHCR_MOCK_PULL_COUNT=0
GHCR_MOCK_TOKEN=""
# shellcheck disable=SC2317 # 由动态载入的 login_and_pull_image 间接调用。
docker() {
	case "$1" in
		pull)
			GHCR_MOCK_PULL_COUNT=$((GHCR_MOCK_PULL_COUNT + 1))
			[[ "$GHCR_MOCK_PULL_COUNT" -ge 2 ]]
			;;
		login)
			read -r GHCR_MOCK_TOKEN
			printf '%s' "$GHCR_MOCK_TOKEN" >"$fixture_dir/ghcr-received-token"
			;;
		*)
			echo "未预期的 docker 调用: $*" >&2
			return 1
			;;
	esac
}
# shellcheck disable=SC2317 # 由动态载入的 login_and_pull_image 间接调用。
prompt() {
	local variable_name="$1"
	if [[ "$variable_name" == "registry_user" ]]; then
		printf -v "$variable_name" '%s' "fixture-user"
	else
		printf -v "$variable_name" '%s' "${3:-}"
	fi
}
# shellcheck disable=SC2317 # 由动态载入的 login_and_pull_image 间接调用。
prompt_secret() {
	printf -v "$1" '%s' "fixture-token"
}
rm -f "$fixture_dir/.ghcr-credentials"
IMAGE_REPOSITORY="ghcr.io/transinfosh/srm"
IMAGE_TAG="0.1.8"
login_and_pull_image >/dev/null
[[ "$(cat "$fixture_dir/ghcr-received-token")" == "fixture-token" ]]
[[ "$(stat -c '%a' "$fixture_dir/.ghcr-credentials")" == "600" ]]
grep -qx 'GHCR_USERNAME=fixture-user' "$fixture_dir/.ghcr-credentials"
grep -qx 'GHCR_TOKEN=fixture-token' "$fixture_dir/.ghcr-credentials"

GHCR_MOCK_PULL_COUNT=0
# shellcheck disable=SC2317 # 由动态载入的 login_and_pull_image 间接调用。
prompt() {
	echo "不应再次询问 GHCR 用户名" >&2
	return 1
}
# shellcheck disable=SC2317 # 由动态载入的 login_and_pull_image 间接调用。
prompt_secret() {
	echo "不应再次询问 GHCR Token" >&2
	return 1
}
login_and_pull_image >/dev/null
[[ "$(cat "$fixture_dir/ghcr-received-token")" == "fixture-token" ]]
unset -f docker prompt prompt_secret
