"""
DiaryVault Memory Layer v0.3 example.

Demonstrates:

* Local encrypted memory creation
* Tamper detection
* Selective context sharing
* RAG and knowledge graph exports
"""

from tempfile import TemporaryDirectory

from diaryvault_memory import (
    ContextRequest,
    MemoryVault,
    VaultExporter,
)


def main() -> None:
    with TemporaryDirectory(
        prefix="diaryvault-memory-example-",
    ) as storage_dir:
        vault = MemoryVault(
            encryption_key="synthetic-example-key",
            storage_dir=storage_dir,
        )

        memories = [
            vault.create(
                content=(
                    "Mina laughed for the first time "
                    "when the dog sneezed."
                ),
                tags=["family", "milestone"],
            ),
            vault.create(
                content=(
                    "We took our first walk together "
                    "under the cherry trees."
                ),
                tags=["family", "outside"],
            ),
            vault.create(
                content=(
                    "Private note for the parents about "
                    "the first difficult night."
                ),
                tags=["family", "private"],
            ),
        ]

        print("DiaryVault Memory Layer v0.3")
        print()

        print("Created memories:")

        for memory in memories:
            tags = ", ".join(memory.metadata.tags)

            print(
                f"  {memory.id[:8]} "
                f"verified={vault.verify(memory)} "
                f"tags={tags}"
            )

        original_content = memories[0].content
        memories[0].content = "Changed after creation"

        print()
        print("Tamper detection:")
        print(
            "  Modified record verified:",
            vault.verify(memories[0]),
        )

        memories[0].content = original_content

        print(
            "  Restored record verified:",
            vault.verify(memories[0]),
        )

        request = ContextRequest(
            agent_id="private-family-recap",
            scope=["family", "milestone"],
            purpose="Prepare a reviewable family recap",
            max_memories=10,
        )

        response = vault.share(
            request,
            allowed_tags=["milestone"],
            denied_tags=["private"],
        )

        print()
        print("Selective context sharing:")
        print(
            "  Shared memories:",
            len(response.shared_memories),
        )
        print(
            "  Response verified:",
            response.verify_all(),
        )

        exporter = VaultExporter(vault)

        rag_chunks = exporter.to_rag_chunks(
            tags=["family"],
            include_hash=True,
        )

        graph = exporter.to_knowledge_graph(
            tags=["family"],
        )

        graph_data = graph.to_dict()

        print()
        print("AI ready exports:")
        print("  RAG chunks:", len(rag_chunks))
        print(
            "  Graph nodes:",
            len(graph_data.get("nodes", [])),
        )
        print(
            "  Graph edges:",
            len(graph_data.get("edges", [])),
        )

        print()
        print(
            "Drafts, suggestions, and explicit approvals: "
            "see review_workflow.py."
        )


if __name__ == "__main__":
    main()
