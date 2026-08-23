#[derive(Clone, Debug)]
pub struct SkillNode {
    pub name: String,
    pub children: Vec<SkillNode>,
}

pub fn skill_tree() -> Vec<SkillNode> {
    vec![
        SkillNode {
            name: "Recon".into(),
            children: vec![
                leaf("subdomain"),
                leaf("port"),
                leaf("fingerprint"),
                leaf("vuln-intel"),
            ],
        },
        SkillNode {
            name: "Scan".into(),
            children: vec![leaf("port-sweep"), leaf("service"), leaf("web")],
        },
        SkillNode {
            name: "Exploit".into(),
            children: vec![leaf("verify"), leaf("payload"), leaf("post-exploit")],
        },
        SkillNode {
            name: "Report".into(),
            children: vec![leaf("findings"), leaf("chain"), leaf("pdf-export")],
        },
    ]
}

fn leaf(name: &str) -> SkillNode {
    SkillNode {
        name: name.into(),
        children: Vec::new(),
    }
}
