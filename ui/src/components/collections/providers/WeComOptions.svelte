<script>
    import Field from "@/components/base/Field.svelte";

    export let key = "";
    export let config = {};
    export let required = false;
    export let title = "WeCom Options";

    $: isRequired = required && config?.enabled;

    if (!config.extra) {
        config.extra = {};
    }
</script>

<div class="section-title">{title}</div>
<Field class="form-field {isRequired ? 'required' : ''}" name="{key}.authURL" let:uniqueId>
    <label for={uniqueId}>AgentID</label>
    <input id={uniqueId} bind:value={config.extra.agentId} required={isRequired} />
</Field>
